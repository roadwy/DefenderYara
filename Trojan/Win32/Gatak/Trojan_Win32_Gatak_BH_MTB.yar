
rule Trojan_Win32_Gatak_BH_MTB{
	meta:
		description = "Trojan:Win32/Gatak.BH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 03 00 00 "
		
	strings :
		$a_03_0 = {01 ef 8d 6e 40 55 56 e8 ?? ?? 00 00 83 c4 08 31 c0 0f 1f 44 00 00 0f b6 4c 05 00 30 0c 07 40 39 d8 72 } //2
		$a_01_1 = {31 c9 c7 44 24 68 74 65 20 6b c7 44 24 60 32 2d 62 79 c7 84 24 ec 00 00 00 6e 64 20 33 } //2
		$a_01_2 = {44 6c 6c 52 65 67 69 73 74 65 72 53 65 72 76 65 72 } //1 DllRegisterServer
	condition:
		((#a_03_0  & 1)*2+(#a_01_1  & 1)*2+(#a_01_2  & 1)*1) >=5
 
}