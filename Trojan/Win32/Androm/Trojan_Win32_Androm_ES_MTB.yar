
rule Trojan_Win32_Androm_ES_MTB{
	meta:
		description = "Trojan:Win32/Androm.ES!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0c 00 0c 00 03 00 00 "
		
	strings :
		$a_01_0 = {8d b4 24 18 05 00 00 6a 0a 8d 7c 2a 10 8b d1 c1 e9 02 f3 a5 8b ca 83 e1 03 f3 a4 01 45 04 ff d3 6a 0a ff d3 6a 0a ff d3 } //10
		$a_81_1 = {4f 6e 65 20 6e 69 67 68 74 20 2d 2d 20 69 74 20 77 61 73 20 6f 6e 20 74 68 65 20 74 77 65 6e 74 69 65 74 68 20 6f 66 20 4d 61 72 63 68 2c 20 31 38 38 38 } //1 One night -- it was on the twentieth of March, 1888
		$a_81_2 = {68 64 69 65 74 72 69 63 68 32 40 68 6f 74 6d 61 69 6c 2e 63 6f 6d } //1 hdietrich2@hotmail.com
	condition:
		((#a_01_0  & 1)*10+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1) >=12
 
}