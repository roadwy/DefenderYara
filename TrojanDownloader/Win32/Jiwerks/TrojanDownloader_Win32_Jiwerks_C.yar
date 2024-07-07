
rule TrojanDownloader_Win32_Jiwerks_C{
	meta:
		description = "TrojanDownloader:Win32/Jiwerks.C,SIGNATURE_TYPE_PEHSTR_EXT,ffffffc9 00 ffffff97 00 07 00 00 "
		
	strings :
		$a_03_0 = {c7 80 9c 00 00 00 30 75 00 00 8b 45 e8 8a 80 11 01 00 00 0a 05 90 01 02 43 00 8b 55 e8 88 82 11 01 00 00 8b 45 e8 c6 80 04 01 00 00 01 90 00 } //100
		$a_01_1 = {72 69 6e 69 6d 61 2e 68 79 70 6b 33 38 2e 63 6f 6d 3a 38 30 38 30 2f } //50 rinima.hypk38.com:8080/
		$a_01_2 = {38 2e 73 7a 68 64 73 6a 2e 63 6f 6d 3a 38 30 38 30 2f } //50 8.szhdsj.com:8080/
		$a_01_3 = {62 6b 2e 64 61 74 6f 6f 6f 2e 63 6f 6d 3a 38 30 38 30 2f } //50 bk.datooo.com:8080/
		$a_01_4 = {62 63 2e 6b 69 35 39 65 6e 67 30 68 73 61 6d 65 73 2e 69 6e 66 6f 3a 38 30 38 30 2f } //50 bc.ki59eng0hsames.info:8080/
		$a_01_5 = {63 6b 32 32 32 2e 63 61 69 6a 69 31 36 38 2e 63 6f 6d 3a 38 30 38 30 2f } //50 ck222.caiji168.com:8080/
		$a_01_6 = {61 3d 6f 26 76 3d 00 00 } //1
	condition:
		((#a_03_0  & 1)*100+(#a_01_1  & 1)*50+(#a_01_2  & 1)*50+(#a_01_3  & 1)*50+(#a_01_4  & 1)*50+(#a_01_5  & 1)*50+(#a_01_6  & 1)*1) >=151
 
}