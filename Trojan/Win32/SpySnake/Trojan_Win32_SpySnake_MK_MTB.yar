
rule Trojan_Win32_SpySnake_MK_MTB{
	meta:
		description = "Trojan:Win32/SpySnake.MK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,14 00 14 00 02 00 00 "
		
	strings :
		$a_01_0 = {6a 00 68 80 00 00 00 6a 03 6a 00 6a 01 68 00 00 00 80 8d 85 ac fd ff ff 50 ff 55 } //10
		$a_01_1 = {89 45 f4 6a 00 8d 45 d4 50 8b 4d e8 51 8b 55 f4 52 8b 45 ec 50 ff 15 } //10
	condition:
		((#a_01_0  & 1)*10+(#a_01_1  & 1)*10) >=20
 
}