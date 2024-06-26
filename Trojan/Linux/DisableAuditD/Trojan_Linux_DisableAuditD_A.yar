
rule Trojan_Linux_DisableAuditD_A{
	meta:
		description = "Trojan:Linux/DisableAuditD.A,SIGNATURE_TYPE_CMDHSTR_EXT,64 00 0a 00 03 00 00 0a 00 "
		
	strings :
		$a_00_0 = {73 00 65 00 72 00 76 00 69 00 63 00 65 00 20 00 61 00 75 00 64 00 69 00 74 00 64 00 20 00 73 00 74 00 6f 00 70 00 } //0a 00  service auditd stop
		$a_00_1 = {72 00 6d 00 20 00 2f 00 76 00 61 00 72 00 2f 00 6c 00 6f 00 67 00 2f 00 61 00 75 00 64 00 69 00 74 00 2f 00 61 00 75 00 64 00 69 00 74 00 2e 00 6c 00 6f 00 67 00 } //0a 00  rm /var/log/audit/audit.log
		$a_00_2 = {72 00 6d 00 20 00 2f 00 65 00 74 00 63 00 2f 00 61 00 75 00 64 00 69 00 73 00 70 00 2f 00 61 00 75 00 64 00 69 00 73 00 70 00 64 00 2e 00 63 00 6f 00 6e 00 66 00 } //00 00  rm /etc/audisp/audispd.conf
	condition:
		any of ($a_*)
 
}