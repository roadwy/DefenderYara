
rule Trojan_Win32_SpySnake_MO_MTB{
	meta:
		description = "Trojan:Win32/SpySnake.MO!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0f 00 0f 00 02 00 00 "
		
	strings :
		$a_01_0 = {83 c4 0c 6a 00 68 80 00 00 00 6a 03 6a 00 6a 01 68 00 00 00 80 b9 04 00 00 00 c1 e1 00 8b 55 0c 8b 04 0a 50 ff 15 } //10
		$a_01_1 = {89 45 f8 6a 00 8d 85 44 ff ff ff 50 8b 4d 94 51 8b 55 f8 52 8b 45 8c 50 ff 15 } //5
	condition:
		((#a_01_0  & 1)*10+(#a_01_1  & 1)*5) >=15
 
}