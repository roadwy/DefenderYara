
rule Trojan_Win32_Sefnit_V{
	meta:
		description = "Trojan:Win32/Sefnit.V,SIGNATURE_TYPE_PEHSTR_EXT,04 00 03 00 04 00 00 "
		
	strings :
		$a_01_0 = {25 73 3f 70 72 6f 74 6f 63 6f 6c 3d 25 64 26 70 72 6f 74 6f 76 65 72 73 69 6f 6e 3d 25 64 26 6f 3d 30 26 70 3d 25 73 26 66 3d 25 64 } //1 %s?protocol=%d&protoversion=%d&o=0&p=%s&f=%d
		$a_01_1 = {2f 67 65 74 74 61 73 6b 73 33 2e 70 68 70 00 } //1
		$a_00_2 = {53 00 45 00 4c 00 45 00 43 00 54 00 20 00 2a 00 20 00 46 00 52 00 4f 00 4d 00 20 00 41 00 6e 00 74 00 69 00 56 00 69 00 72 00 75 00 73 00 50 00 72 00 6f 00 64 00 75 00 63 00 74 00 } //1 SELECT * FROM AntiVirusProduct
		$a_03_3 = {56 8b cf 80 f3 ?? e8 ?? ?? ?? ?? 46 88 18 83 fe 2d 72 e7 } //2
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_00_2  & 1)*1+(#a_03_3  & 1)*2) >=3
 
}