
rule Trojan_Win32_FileCoder_ARAX_MTB{
	meta:
		description = "Trojan:Win32/FileCoder.ARAX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 03 00 00 02 00 "
		
	strings :
		$a_01_0 = {41 d1 eb 83 e8 01 89 4d fc 89 45 f4 0f 85 6b ff ff ff } //02 00 
		$a_00_1 = {47 00 6c 00 6f 00 62 00 61 00 6c 00 5c 00 46 00 53 00 57 00 69 00 70 00 65 00 72 00 } //02 00  Global\FSWiper
		$a_00_2 = {5c 00 5a 00 4c 00 57 00 50 00 2e 00 74 00 6d 00 70 00 } //00 00  \ZLWP.tmp
	condition:
		any of ($a_*)
 
}