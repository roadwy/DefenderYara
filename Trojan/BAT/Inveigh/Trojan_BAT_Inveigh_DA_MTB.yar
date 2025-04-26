
rule Trojan_BAT_Inveigh_DA_MTB{
	meta:
		description = "Trojan:BAT/Inveigh.DA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,1a 00 1a 00 07 00 00 "
		
	strings :
		$a_81_0 = {53 70 6f 6f 66 65 72 49 50 76 36 } //1 SpooferIPv6
		$a_81_1 = {4c 69 73 74 65 6e 65 72 49 50 76 36 } //1 ListenerIPv6
		$a_81_2 = {53 6e 69 66 66 65 72 49 50 76 36 } //1 SnifferIPv6
		$a_81_3 = {44 48 43 50 76 36 20 73 70 6f 6f 66 69 6e 67 } //1 DHCPv6 spoofing
		$a_81_4 = {4d 44 4e 53 50 61 63 6b 65 74 } //1 MDNSPacket
		$a_81_5 = {4c 44 41 50 20 6c 69 73 74 65 6e 65 72 } //20 LDAP listener
		$a_81_6 = {48 54 54 50 53 20 6c 69 73 74 65 6e 65 72 } //1 HTTPS listener
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1+(#a_81_5  & 1)*20+(#a_81_6  & 1)*1) >=26
 
}