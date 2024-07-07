
rule Trojan_Win32_Terraloader_LKA_MTB{
	meta:
		description = "Trojan:Win32/Terraloader.LKA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 02 00 00 "
		
	strings :
		$a_01_0 = {03 5d 24 89 5c 24 14 8b 5c 24 68 8b 6c 24 0c 03 5d 20 89 5c 24 18 8b 6c 24 0c 8b 5d 18 81 fb 00 10 00 00 7f 0d } //1
		$a_03_1 = {c7 44 24 10 00 00 00 00 eb 00 b8 10 27 00 00 3b 44 24 90 01 01 0f 8c 8c 00 00 00 90 00 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*1) >=1
 
}