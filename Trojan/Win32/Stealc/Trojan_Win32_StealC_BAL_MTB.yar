
rule Trojan_Win32_StealC_BAL_MTB{
	meta:
		description = "Trojan:Win32/StealC.BAL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {30 04 3e 46 3b f3 7c f3 } //1
		$a_03_1 = {88 04 31 81 3d 90 01 04 ab 05 00 00 75 90 0a 32 00 8b 0d 90 01 04 89 4c 24 90 01 01 b8 31 a2 00 00 01 44 24 90 01 01 8b 54 24 90 01 01 8a 04 32 8b 0d 90 00 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}