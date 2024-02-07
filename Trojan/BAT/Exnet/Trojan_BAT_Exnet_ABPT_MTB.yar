
rule Trojan_BAT_Exnet_ABPT_MTB{
	meta:
		description = "Trojan:BAT/Exnet.ABPT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 04 00 00 05 00 "
		
	strings :
		$a_01_0 = {47 41 64 6d 69 6e 4c 69 62 2e 50 72 6f 70 65 72 74 69 65 73 2e 52 65 73 6f 75 72 63 65 73 2e 72 65 73 6f 75 72 63 65 73 } //01 00  GAdminLib.Properties.Resources.resources
		$a_01_1 = {47 65 74 4f 62 6a 65 63 74 } //01 00  GetObject
		$a_01_2 = {49 6e 76 6f 6b 65 4d 65 6d 62 65 72 } //01 00  InvokeMember
		$a_01_3 = {47 00 41 00 64 00 6d 00 69 00 6e 00 4c 00 69 00 62 00 } //00 00  GAdminLib
	condition:
		any of ($a_*)
 
}