
rule Trojan_Win32_StealC_BAL_MTB{
	meta:
		description = "Trojan:Win32/StealC.BAL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {30 04 3e 46 3b f3 7c f3 } //1
		$a_03_1 = {88 04 31 81 3d ?? ?? ?? ?? ab 05 00 00 75 90 0a 32 00 8b 0d ?? ?? ?? ?? 89 4c 24 ?? b8 31 a2 00 00 01 44 24 ?? 8b 54 24 ?? 8a 04 32 8b 0d } //1
	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}