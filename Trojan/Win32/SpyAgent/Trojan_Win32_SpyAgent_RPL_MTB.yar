
rule Trojan_Win32_SpyAgent_RPL_MTB{
	meta:
		description = "Trojan:Win32/SpyAgent.RPL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 06 00 00 01 00 "
		
	strings :
		$a_01_0 = {2e 75 6e 67 61 69 6e 61 } //01 00  .ungaina
		$a_01_1 = {2e 72 65 66 75 74 61 62 } //01 00  .refutab
		$a_01_2 = {2e 69 6d 70 6c 75 6d 65 } //01 00  .implume
		$a_01_3 = {2e 74 75 72 62 6f 64 79 } //01 00  .turbody
		$a_01_4 = {2e 63 61 6c 76 69 6e 69 } //01 00  .calvini
		$a_01_5 = {2e 62 65 63 69 72 63 6c } //00 00  .becircl
	condition:
		any of ($a_*)
 
}