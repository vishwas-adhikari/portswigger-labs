Access Control & Privilege Escalation — Theory

1. Introduction

- What is the vulnerability?
  Access control (authorization) is the mechanism by which an application enforces constraints on which users or systems can perform specific actions or access particular resources. Broken access control occurs when these constraints are not properly enforced server-side, allowing unauthorized users to act outside their intended permissions.
- Where does it commonly occur?
  Commonly occurs in web applications, REST APIs, GraphQL endpoints, administrative portals, multi-tenant SaaS platforms, and multi-step transaction workflows.
- What application behavior is involved?
  Access control relies on authentication (confirming user identity) and session management (identifying subsequent requests). Access control itself determines whether an authenticated (or unauthenticated) session is permitted to execute a requested HTTP method on a targeted URL or resource ID.

2. Why It Matters

- Confidentiality impact: High to Critical. Unauthorized exposure of sensitive data, PII, internal records, administrator credentials, or cross-tenant records.
- Integrity impact: High to Critical. Unauthorized modification, deletion, or creation of system settings, user profiles, transactional records, or database entries.
- Availability impact: Medium to High. Unauthorized deletion of key system configuration, account lockouts, or administrative service disruption.
- User / business impact: Full tenant compromise, severe regulatory compliance penalties (GDPR, HIPAA, PCI-DSS), reputational damage, and financial loss.
- OWASP Top 10 mapping: OWASP Top 10:2021 — A01:2021 Broken Access Control (Ranked #1 most critical security risk).

3. How It Works

- Normal behavior: A request arrives at the application server with a valid session identifier. The application validates the session, identifies the user's role and identity, verifies that the user is explicitly authorized to access the requested resource or endpoint, and returns the response if permitted.
- Vulnerable behavior: The application relies on client-side controls, hidden links, trust in user-supplied parameters (e.g., `role=admin`, `userId=1002`), unvalidated request headers (e.g., `X-Original-URL`, `Referer`), or omits authorization checks on specific endpoints or process steps.
- Trust boundary: The trust boundary exists between the untrusted client (browser/HTTP client) and the trusted server. Broken access controls occur whenever access control decisions rely on client-supplied data without server-side verification against session state.
- Technical flow:
  1. Client sends HTTP request (e.g., `GET /admin/deleteUser?id=45` or `GET /myaccount?id=1002`).
  2. Front-end or proxy routes request to application controller.
  3. Server fails to check session role or resource ownership.
  4. Application executes action or fetches resource data and returns it to the client.

4. Types and Variations

| Type | Explanation | Key distinction |
|------|-------------|-----------------|
| Vertical Privilege Escalation | A lower-privileged user gains access to functionality reserved for higher-privileged users (e.g., regular user accessing admin functions). | Elevation of role/privilege level. |
| Horizontal Privilege Escalation | A user gains access to resources belonging to another user with the same privilege level (e.g., User A accessing User B's account). | Lateral movement across users at the same privilege level. |
| Horizontal to Vertical Escalation | A horizontal escalation against a high-privileged account (e.g., obtaining an admin password/session) leads to vertical elevation. | Starts laterally, ends with administrative compromise. |
| Insecure Direct Object References (IDOR) | Subcategory of horizontal/vertical access control where user input directly references database objects or files without authorization checks. | Parameter tampering directly addressing internal object IDs. |
| Context-Dependent Access Control | Bypassing authorization rules tied to application state or workflow order (e.g., skipping payment step to complete order). | State/workflow sequence violation. |
| Platform / Routing Misconfigurations | Bypassing framework-level or reverse-proxy access rules via HTTP method substitution or URL override headers. | Infrastructure/routing discrepancies vs logic errors. |

5. Root Causes

- Lack of central, server-side access control policy enforcement.
- Relying on security by obscurity (hiding admin links or using unguessable URLs without enforcing access checks).
- Trusting user-controllable input for authorization (request parameters, cookies, hidden form fields, headers).
- Missing access control checks on specific HTTP methods or multi-step workflow endpoints.
- Inconsistent URL parsing or path matching between front-end reverse proxies and back-end application frameworks.

6. Exploitation Techniques

6.1 Unprotected Administrative Functionality

- Concept: Browsing directly to administrative URLs that are unlinked in standard user UIs or hidden in client-side scripts.
- When it applies: When administrative functions exist at known paths (`/admin`, `/administrator`) or obfuscated paths (`/admin-panel-yb556`) disclosed in JavaScript.
- Testing steps:
  1. Inspect `robots.txt`, `sitemap.xml`, JavaScript assets, and inline code.
  2. Perform endpoint brute-forcing/fuzzing using wordlists (e.g., `dirbuster`, `ffuf`).
  3. Attempt direct GET/POST requests to discovered administrative endpoints while authenticated as a low-privileged user.
- Example payload/request:
  ```http
  GET /administrator-panel-yb556 HTTP/1.1
  Host: vulnerable-website.com
  Cookie: session=regular_user_session
  ```
- Why it works: The server relies on client UI hiding rather than enforcing role checks on the back-end route handler.
- Limitations / common mistakes: Assuming an unpredictable URL is secure ("security by obscurity").

6.2 Parameter-Based Role Tampering

- Concept: Modifying user-controllable request parameters, cookies, or hidden fields that dictate authorization decisions.
- When it applies: Applications that store role flags or user levels in client-modifiable state.
- Testing steps:
  1. Capture login, profile update, or request traffic in Burp Suite.
  2. Identify parameters like `admin=false`, `role=1`, `is_admin=0`, `group=user`.
  3. Modify parameter values to elevated states (`admin=true`, `role=2`, `is_admin=1`) and resend.
- Example payload/request:
  ```http
  POST /myaccount/update HTTP/1.1
  Host: vulnerable-website.com
  Cookie: session=user_session

  role=admin&email=user%40example.com
  ```
- Why it works: Server accepts client-supplied role values without verifying them against trusted session data.
- Limitations / common mistakes: Server-side validation may overwrite values on certain routes while leaving others vulnerable.

6.3 Platform Misconfiguration & Override Headers

- Concept: Circumventing proxy/WAF access rules by utilizing custom HTTP headers or alternative HTTP methods.
- When it applies: When front-end proxies enforce URL restrictions but back-end frameworks process rewrite headers like `X-Original-URL` or `X-Rewrite-URL`, or accept non-standard methods (e.g., `GET` instead of `POST`).
- Testing steps:
  1. Send request to protected endpoint (e.g., `POST /admin/deleteUser`) → observe `403 Forbidden`.
  2. Send request to root (`POST /`) with `X-Original-URL: /admin/deleteUser`.
  3. Change HTTP method from `POST` to `GET` or `PUT`.
- Example payload/request:
  ```http
  POST / HTTP/1.1
  Host: vulnerable-website.com
  X-Original-URL: /admin/deleteUser
  Cookie: session=regular_user_session

  username=target_user
  ```
- Why it works: The proxy checks `/` (allowed) while the back-end framework processes `/admin/deleteUser` without repeating access control checks.
- Limitations / common mistakes: Headers may be stripped by strict reverse proxies.

6.4 Insecure Direct Object References (IDOR) & Parameter Tampering

- Concept: Modifying resource identifier parameters to access or manipulate data belonging to other users.
- When it applies: REST endpoints or query parameters containing predictable or discoverable IDs (`id=1001`, `guid=...`).
- Testing steps:
  1. Identify endpoints referencing object IDs (`GET /myaccount?id=1001`, `GET /downloadReport?fileId=884`).
  2. Swap `id` value with another user's ID (`1002`).
  3. If GUIDs are used, look for ID disclosure in public comments, API responses, or profile pages.
  4. Check responses for data leakage even if HTTP 302/403 status is returned.
- Example payload/request:
  ```http
  GET /myaccount?id=1002 HTTP/1.1
  Host: vulnerable-website.com
  Cookie: session=user_1001_session
  ```
- Why it works: Server retrieves object by key without verifying if object owner matches authenticated session user.
- Limitations / common mistakes: Overlooking data leakage contained inside `302 Found` redirect response bodies.

6.5 Multi-Step Process & Referer-Based Bypasses

- Concept: Skipping initial validation steps in multi-stage workflows or forging `Referer` headers to satisfy naive origin checks.
- When it applies: Multi-step forms (Step 1 -> Step 2 -> Confirm Step 3) or sub-pages checking `Referer: /admin`.
- Testing steps:
  1. Send request directly to final step (Step 3) omitting initial step parameters.
  2. Add or modify `Referer: https://vulnerable-website.com/admin` header on requests to restricted endpoints.
- Example payload/request:
  ```http
  POST /admin/deleteUser HTTP/1.1
  Host: vulnerable-website.com
  Referer: https://vulnerable-website.com/admin
  Cookie: session=regular_user_session

  username=victim
  ```
- Why it works: Developers assume prior steps or trusted referers guarantee user authorization.
- Limitations / common mistakes: Modern browsers and CORS policies restrict `Referer` header manipulation in standard client environments.

7. Vulnerable Code vs Secure Code

Vulnerable Example

Language: Java (Spring Boot / Servlet)

```java
// Vulnerable Controller Method
@PostMapping("/admin/deleteUser")
public ResponseEntity<String> deleteUser(@RequestParam String username, HttpServletRequest request) {
    // Vulnerable: Relies on client parameter or missing role check
    String role = request.getParameter("role"); 
    if ("admin".equals(role)) {
        userService.deleteUser(username);
        return ResponseEntity.ok("User deleted");
    }
    return ResponseEntity.status(403).body("Access Denied");
}
```

Why it is vulnerable: The authorization decision trusts the client-supplied `role` parameter rather than checking the authenticated user's session authority on the server.

Secure Example

Language: Java (Spring Security)

```java
// Secure Controller Method
@PreAuthorize("hasRole('ROLE_ADMIN')")
@PostMapping("/admin/deleteUser")
public ResponseEntity<String> deleteUser(@RequestParam String username, @AuthenticationPrincipal UserDetails currentUser) {
    // Secure: Server-side role check enforced by framework before method execution
    userService.deleteUser(username);
    return ResponseEntity.ok("User deleted");
}
```

Why it is safer: Access is denied by default unless the server-validated session security context explicitly holds `ROLE_ADMIN`.

8. Practical Testing Methodology

1. Reconnaissance: Map all application endpoints, user roles, workflow steps, JavaScript files, and API documentation.
2. Identify the attack surface: List all endpoints handling sensitive data, administrative tasks, user profile modifications, and object retrievals.
3. Identify user-controlled inputs: Note all URL parameters, path segments, request headers (`Referer`, `X-Original-URL`), body fields, and cookies influencing state or object lookup.
4. Test relevant security assumptions:
   - Attempt vertical privilege escalation by invoking admin routes as low-privilege/guest users.
   - Attempt horizontal escalation by altering resource IDs (`id=1001` → `1002`).
   - Test method switching (`POST` → `GET`/`PUT`) and path variations (`/admin/deleteUser` vs `/ADMIN/deleteUser` or `/admin/deleteUser/`).
5. Validate the behavior: Inspect response status codes, body contents (check for data leakage in 302/403 responses), and database state change.
6. Assess the impact: Determine if the flaw enables full administrative takeover, cross-tenant data exfiltration, or unauthorized state alteration.

9. Detection and Prevention

Detection

- Manual testing: Use multi-account browser sessions (e.g., Burp Suite Autorize extension) to automatically replay requests with different role tokens.
- Burp Suite: Utilize Burp Repeater, Match and Replace rules, and extensions like *Autorize* or *AutoRepeater*.
- Code review: Audit route annotations, authorization middleware, database queries for missing ownership `WHERE` clauses.
- Automated testing / monitoring: Implement automated integration tests testing every API endpoint with unauthenticated, standard, and admin credentials.

### Prevention

- Enforce access control server-side at a centralized authorization layer.
- Deny access by default for all non-public resources.
- Validate resource ownership on every request (e.g., `WHERE item_id = :id AND user_id = :session_user_id`).
- Avoid client-side role parameters, hidden fields, or trusting HTTP headers like `Referer` or `X-Original-URL`.
- Disable Spring `useSuffixPatternMatch` and enforce consistent URL routing/casing rules.

10. Tools

| Tool | Purpose |
|------|---------|
| Burp Suite Professional | Intercepting, modifying HTTP requests, and analyzing responses. |
| Autorize (Burp Extension) | Automatic access control detection by replaying requests with low-privilege tokens. |
| AutoRepeater (Burp Extension) | Automated request duplication and modification across session contexts. |
| ffuf / Dirbuster | Directory and endpoint brute-forcing to uncover unlinked admin interfaces. |

11. OWASP / CWE Mapping

- OWASP category and version: OWASP Top 10:2021 Category A01 — Broken Access Control.
- Why the mapping applies: Applies whenever authorization mechanisms fail to enforce least privilege or separation of duties.
- Related CWE:
  - CWE-284: Improper Access Control
  - CWE-285: Improper Authorization
  - CWE-639: Authorization Bypass Through User-Controlled Key (IDOR)
  - CWE-862: Missing Authorization
- Related vulnerability classes: Privilege Escalation, Insecure Direct Object References, Missing Function Level Access Control.

12. Real-World Scenarios

- E-Commerce Order Modification: A user updates quantity or pricing on `/checkout/step3` by bypassing client-side validation on step 1 & 2.
- Healthcare Tenant Data Leakage: A doctor logged into Hospital A changes `hospital_id=1` to `hospital_id=2` in a URL parameter and views patient records from Hospital B.
- SaaS Organization Takeover: A standard user edits `org_role=member` to `org_role=owner` in a JSON request body on their profile settings page.

13. Interview Preparation

Important Questions

1. What is the difference between Authentication and Authorization?
2. What is the difference between Vertical and Horizontal Privilege Escalation?
3. What is an IDOR vulnerability, and how does it relate to Access Control?
4. How can platform routing discrepancies (like HTTP method switching or override headers) bypass access controls?
5. How would you design a secure authorization check for a multi-tenant application?

### Key Points to Remember

- Never rely on client-side controls or URL obfuscation ("security by obscurity").
- Access control must be enforced on the server for every single request and workflow step.
- Deny access by default.
- Always check both role permissions (vertical) and object ownership (horizontal).

60–90 Second Explanation

"Broken Access Control occurs when an application fails to properly enforce permissions on the server, allowing users to access resources or perform actions outside their intended permissions. It manifests as Vertical Privilege Escalation, where a regular user accesses administrative functions, or Horizontal Privilege Escalation (such as IDOR), where a user accesses data belonging to another peer. Common root causes include relying on client-side role flags, hiding URLs instead of enforcing checks, and failing to validate object ownership in database queries. To prevent it, applications must enforce server-side authorization checks by default using a centralized access control mechanism that validates both user role and resource ownership for every request."

How I Would Test It in a Real Product

"I set up two testing accounts at different privilege levels (e.g., Admin and Standard User) and a second Standard User account for horizontal testing. I map the application's attack surface in Burp Suite using the high-privilege account first. Then, using tools like Burp Autorize, I replay all administrative requests using the low-privilege session cookie to identify unprotected functions (vertical escalation). For parameter-based endpoints (such as `/user/profile?id=X`), I swap the object IDs to test for IDORs (horizontal escalation), while also testing HTTP method variations and header overrides like `X-Original-URL`."

14. References

- PortSwigger Web Security Academy: https://portswigger.net/web-security/access-control
- OWASP Top 10 A01:2021 — Broken Access Control: https://owasp.org/Top10/A01_2021-Broken_Access_Control/
- CWE-862 (Missing Authorization): https://cwe.mitre.org/data/definitions/862.html
- CWE-639 (Insecure Direct Object Reference): https://cwe.mitre.org/data/definitions/639.html
