
rule Trojan_Win32_MixLoader_RB_MTB{
	meta:
		description = "Trojan:Win32/MixLoader.RB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 02 00 00 "
		
	strings :
		$a_01_0 = {55 8b ec 6a 00 e8 1a 45 04 00 85 c0 74 0f e8 dd 00 00 00 e8 38 75 fd ff e8 23 4e fe ff e9 } //5
		$a_01_1 = {41 00 53 00 6d 00 61 00 72 00 74 00 43 00 6f 00 72 00 65 00 2e 00 65 00 78 00 65 00 } //1 ASmartCore.exe
	condition:
		((#a_01_0  & 1)*5+(#a_01_1  & 1)*1) >=6
 
}