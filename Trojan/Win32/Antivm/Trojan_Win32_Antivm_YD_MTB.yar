
rule Trojan_Win32_Antivm_YD_MTB{
	meta:
		description = "Trojan:Win32/Antivm.YD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 05 00 00 01 00 "
		
	strings :
		$a_01_0 = {2a 00 45 00 52 00 41 00 57 00 4d 00 56 00 2a 00 } //01 00  *ERAWMV*
		$a_01_1 = {2a 00 4c 00 41 00 55 00 54 00 52 00 49 00 56 00 2a 00 } //01 00  *LAUTRIV*
		$a_01_2 = {2a 00 58 00 4f 00 42 00 56 00 2a 00 } //01 00  *XOBV*
		$a_01_3 = {6c 00 6c 00 64 00 2e 00 6c 00 6c 00 64 00 65 00 69 00 62 00 73 00 } //01 00  lld.lldeibs
		$a_01_4 = {6c 00 6c 00 64 00 2e 00 70 00 6c 00 65 00 68 00 67 00 62 00 64 00 } //00 00  lld.plehgbd
	condition:
		any of ($a_*)
 
}