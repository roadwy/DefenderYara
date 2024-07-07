
rule Trojan_Win32_StopCrypt_DX_MTB{
	meta:
		description = "Trojan:Win32/StopCrypt.DX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {33 c3 2b f8 89 7d e0 8b 45 d4 29 45 fc ff 4d e4 0f 85 } //1
		$a_01_1 = {c7 45 a4 2c 02 26 1e c7 45 6c fe 0b df 0e c7 45 ac b6 a9 2a 0e c7 45 e4 99 de 64 12 c7 45 08 31 08 38 76 c7 45 a8 13 56 26 0c } //1
		$a_01_2 = {81 fe aa b0 e7 00 7f 0d 46 81 fe 76 24 ec 5a 0f 8c } //1
		$a_01_3 = {77 6f 72 6d 73 2e 74 78 74 } //1 worms.txt
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}