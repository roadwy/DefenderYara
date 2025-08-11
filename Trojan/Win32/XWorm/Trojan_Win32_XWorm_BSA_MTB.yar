
rule Trojan_Win32_XWorm_BSA_MTB{
	meta:
		description = "Trojan:Win32/XWorm.BSA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0f 00 0f 00 02 00 00 "
		
	strings :
		$a_01_0 = {56 8b f1 8b 4e 24 85 c9 74 15 8b 11 3b ce 0f 95 c0 0f b6 c0 50 ff 52 10 c7 46 24 00 } //10
		$a_01_1 = {8b 45 c0 8d 4d c0 6a 14 68 a8 7b 68 00 ff 10 8b 56 0c 8d 4d c0 e8 39 36 fb ff 8b f8 6a 09 68 9c 7b 68 00 8b 0f 8b 11 8b cf ff d2 8b 56 24 } //5
	condition:
		((#a_01_0  & 1)*10+(#a_01_1  & 1)*5) >=15
 
}