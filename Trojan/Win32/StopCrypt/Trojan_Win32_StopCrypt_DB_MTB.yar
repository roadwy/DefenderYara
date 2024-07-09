
rule Trojan_Win32_StopCrypt_DB_MTB{
	meta:
		description = "Trojan:Win32/StopCrypt.DB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 02 00 00 "
		
	strings :
		$a_03_0 = {8a 8c 06 3b 2d 0b 00 8b 15 [0-04] 88 0c 16 a1 [0-04] 83 f8 44 75 16 } //2
		$a_01_1 = {c7 84 24 bc 01 00 00 e5 9a 40 22 c7 84 24 78 02 00 00 95 54 fe 1a c7 84 24 70 01 00 00 87 64 58 7c c7 84 24 48 01 00 00 47 cc 65 36 ff d7 81 fe aa dd 18 02 7f 0d 46 81 fe 76 24 ec 5a 0f 8c } //2
	condition:
		((#a_03_0  & 1)*2+(#a_01_1  & 1)*2) >=4
 
}