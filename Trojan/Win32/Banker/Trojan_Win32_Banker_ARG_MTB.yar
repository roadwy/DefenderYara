
rule Trojan_Win32_Banker_ARG_MTB{
	meta:
		description = "Trojan:Win32/Banker.ARG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 04 00 00 "
		
	strings :
		$a_01_0 = {83 c0 05 2b d0 8b c2 c3 } //2
		$a_03_1 = {c6 03 e8 8d 56 04 8b c3 e8 ?? ?? ?? ?? 89 43 01 8b 07 89 43 05 89 1f 83 c3 0d 8b c3 2b c6 3d fc 0f 00 00 7c db } //2
		$a_80_2 = {4e 65 74 57 6b 73 74 61 47 65 74 49 6e 66 6f } //NetWkstaGetInfo  1
		$a_80_3 = {45 78 74 72 65 6d 65 20 49 6e 6a 65 63 74 6f 72 2e 65 78 65 } //Extreme Injector.exe  3
	condition:
		((#a_01_0  & 1)*2+(#a_03_1  & 1)*2+(#a_80_2  & 1)*1+(#a_80_3  & 1)*3) >=8
 
}