List of parameters used in BVSS:

1. Base score - this metric measures the impact of tokens/crypto loss.
   S - if crypto/tokens could be stollen;
   L - if crypto/tokens could be lost;
   N - none

2. Attack vector - this metric reflects the context by which vulnerability exploitation is possible. The Score increases the more remote an attacker can be in order to exploit the vulnerable component.
   N - Network: A vulnerability exploitable with network access means the vulnerable component is bound to the network stack and the attacker's path is through OSI layer 3 (the network layer). Such a vulnerability is often termed "remotely exploitable" and can be thought of as an attack being exploitable one or more network hops away.
   P - Physical: A vulnerability exploitable with physical access requires the attacker to physically touch or manipulate the vulnerable component. Physical interaction may be brief or persistent.

3. Attack complexity - this metric describes the conditions beyond the attacker's control that must exist in order to exploit the vulnerability. Such conditions may require the collection of more information about the target, the presence of certain system configuration settings, or computational exceptions.
   H - High: A successful attack depends on conditions beyond the attacker's control. That is, a successful attack cannot be accomplished at will, but requires the attacker to invest in some measurable amount of effort in preparation or execution against the vulnerable component before a successful attack can be expected. For example, a successful attack may require the attacker: to perform target-specific reconnaissance; to prepare the target environment to improve exploit reliability; or to inject herself into the logical network path between the target and the resource requested by the victim in order to read and/or modify network communications.
   L - Low: Specialized access conditions or extenuating circumstances do not exist. An attacker can expect repeatable success against the vulnerable component.

4. Privileges required - this metric describes the level of privileges an attacker must possess before successfully exploiting the vulnerability. This Score increases as fewer privileges are required.
   N - None: The attacker is unauthorized prior to attack, and therefore does not require any access to settings or files to carry out an attack.
   R - Required: The attacker is authorized with (i.e. requires) privileges that provide user capabilities that could normally affect component-wide settings.

5. User Interaction required - this metric captures the requirement for a user, other than the attacker, to participate in the successful compromise the vulnerable component. This metric determines whether the vulnerability can be exploited solely at the will of the attacker, or whether a separate user (or user-initiated process) must participate in some manner. The Score is highest when no user interaction is required.
   N - None: The vulnerable system can be exploited without any interaction from any user.
   R - Required: Successful exploitation of this vulnerability requires a user to take some action before the vulnerability can be exploited.

6. Scope - this metric shows whether a successful attack impact a component other than the vulnerable component? If so, the Score increases and the Confidentiality, Integrity and Authentication metrics should be scored relative to the impacted component.
   U - Unchanged: An exploited vulnerability can only affect resources managed by the same authority. In this case the vulnerable component and the impacted component are the same.
   C - Changed: An exploited vulnerability can affect resources beyond the authorization privileges intended by the vulnerable component. In this case the vulnerable component and the impacted component are different.

7. Confidentiality Impact - this metric measures the impact to the confidentiality of the information resources managed by a software component due to a successfully exploited vulnerability. Confidentiality refers to limiting information access and disclosure to only authorized users, as well as preventing access by, or disclosure to, unauthorized ones.
   N - None: There is not any confidentiality impact on application.
   L - Low: There is some loss of confidentiality. Access to some restricted information is obtained, but the attacker does not have control over what information is obtained, or the amount or kind of loss is constrained. The information disclosure does not cause a direct, serious loss to the impacted component.
   M - Medium: Most of the confidentiality is compromised. Attacker has access to the most of the resources. The disclosed information presents impact.
   H - High: There is total loss of confidentiality, resulting in all resources within the impacted component being divulged to the attacker. Alternatively, access to only some restricted information is obtained, but the disclosed information presents a direct, serious impact.

8. Integrity Impact - this metric measures the impact to integrity of a successfully exploited vulnerability. Integrity refers to the trustworthiness and veracity of information.
   N - None: There is not any integrity impact on application.
   L - Low: Modification of data is possible, but the attacker does not have control over the consequence of a modification, or the amount of modification is constrained. The data modification does not have a direct, serious impact on the impacted component.
   M - Medium: Most of the confidentiality is compromised. Attacker has access to the most of the resources. The disclosed information presents impact.
   H - High: There is a total loss of integrity, or a complete loss of protection. For example, the attacker is able to modify any/all files protected by the impacted component.

9. Availability Impact - this metric measures the impact to the availability of the impacted component resulting from a successfully exploited vulnerability. It refers to the loss of availability of the impacted component itself, such as a networked service (e.g., web, database, email). Since availability refers to the accessibility of information resources, attacks that consume network bandwidth, processor cycles, or disk space all impact the availability of an impacted component.
   N - None: There is not any availability impact on application.
   L - Low: There is low reduced performance or interruptions in resource availability. Even if repeated exploitation of the vulnerability is possible, the attacker does not have the ability to completely deny service to legitimate users. The resources in the impacted component are either partially available all of the time, or fully available only some of the time, but overall there is no direct, serious consequence to the impacted component.
   M - Medium: There is reduced performance of resource availability.
   H - High: There is total loss of availability, resulting in the attacker being able to fully deny access to resources in the impacted component; this loss is either sustained (while the attacker continues to deliver the attack) or persistent (the condition persists even after the attack has completed). Alternatively, the attacker has the ability to deny some availability, but the loss of availability presents a direct, serious consequence to the impacted component (e.g., the attacker cannot disrupt existing connections, but can prevent new connections; the attacker can repeatedly exploit a vulnerability that, in each instance of a successful attack, leaks a only small amount of memory, but after repeated exploitation causes a service to become completely unavailable).

10. Confidentiality Value - this metric shows the value of confidentiality for specific application.
    N - None: Confidentiality doesnt have any value for this application.
    L - Low: Condfidentiality has low value for this application.
    M - Medium: Condfidentiality has medium value for this application.
    H - High: Condfidentiality has high value for this application.

11. Integrity Value - this metric shows the value of integrity for specific application.
    N - None: Integrity doesnt have any value for this application.
    L - Low: Integrity has low value for this application.
    M - Medium: Integrity has medium value for this application.
    H - High: Integrity has high value for this application.

12. Availability Value - this metric shows the value of availability for specific application.
    N - None: Availability doesnt have any value for this application.
    L - Low: Availability has low value for this application.
    M - Medium: Availability has medium value for this application.
    H - High: Availability has high value for this application.
