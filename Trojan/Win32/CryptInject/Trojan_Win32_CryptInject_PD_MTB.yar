
rule Trojan_Win32_CryptInject_PD_MTB{
	meta:
		description = "Trojan:Win32/CryptInject.PD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {8a 95 00 ff ff ff 88 55 e3 0f be 45 ef 83 e0 0f c1 e0 04 0f be 4d e3 83 e1 0f 0b c1 8b 55 0c 03 55 c8 88 02 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}
rule Trojan_Win32_CryptInject_PD_MTB_2{
	meta:
		description = "Trojan:Win32/CryptInject.PD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,15 00 15 00 03 00 00 "
		
	strings :
		$a_02_0 = {81 fe ab 4e 19 00 75 06 ff 15 ?? ?? ?? 00 46 81 fe 46 ed 54 00 7c dd 8b 4d fc 5f 5e 33 cd 5b e8 ?? 00 00 00 8b e5 5d c3 } //10
		$a_02_1 = {12 0f 00 00 75 08 6a 00 ff 15 ?? ?? ?? 00 [0-05] 00 69 ?? fd 43 03 00 [0-05] 00 81 05 ?? ?? ?? 00 c3 9e 26 00 81 3d ?? ?? ?? 00 cf 12 00 00 0f b7 ?? ?? ?? ?? 00 75 0a 6a 00 6a 00 ff 15 ?? ?? ?? 00 } //10
		$a_02_2 = {81 ff 69 04 00 00 75 ?? 6a 00 ff 15 ?? ?? ?? 00 6a 00 6a 00 [0-08] ff 15 ?? ?? ?? 00 [0-70] 30 ?? ?? 46 3b f7 7c } //1
	condition:
		((#a_02_0  & 1)*10+(#a_02_1  & 1)*10+(#a_02_2  & 1)*1) >=21
 
}