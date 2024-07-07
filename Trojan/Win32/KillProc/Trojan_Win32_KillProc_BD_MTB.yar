
rule Trojan_Win32_KillProc_BD_MTB{
	meta:
		description = "Trojan:Win32/KillProc.BD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 02 00 00 "
		
	strings :
		$a_03_0 = {57 6a 01 8d 55 dc 6a 01 52 e8 90 02 04 80 75 dc fb 56 6a 01 8d 45 dc 6a 01 50 e8 90 02 04 43 83 c4 20 3b 9d 6c fd ff ff 72 90 00 } //2
		$a_01_1 = {53 00 6f 00 67 00 6f 00 75 00 50 00 69 00 6e 00 79 00 69 00 6e 00 2e 00 6c 00 6f 00 63 00 61 00 6c 00 } //2 SogouPinyin.local
	condition:
		((#a_03_0  & 1)*2+(#a_01_1  & 1)*2) >=4
 
}