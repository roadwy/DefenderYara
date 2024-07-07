
rule Trojan_Win32_Downacoder_A{
	meta:
		description = "Trojan:Win32/Downacoder.A,SIGNATURE_TYPE_PEHSTR_EXT,ffffff90 01 ffffff90 01 04 00 00 "
		
	strings :
		$a_00_0 = {20 4c 48 4f 53 54 20 4c 50 4f 52 54 0a 0a 45 78 61 6d 70 6c 65 3a 0a } //100
		$a_00_1 = {43 6f 6e 6e 65 63 74 69 6e 67 20 74 6f 20 63 6f 6e 74 72 6f 6c 20 73 65 72 76 65 72 3a 20 25 73 3a 25 73 0a 00 } //100
		$a_00_2 = {77 69 6e 73 6f 63 6b 00 55 6e 61 62 6c 65 20 74 6f 20 67 65 74 20 68 6f 73 74 6e 61 6d 65 00 } //100
		$a_03_3 = {41 b9 40 00 00 00 41 b8 00 10 00 00 90 02 08 b9 00 00 00 00 90 02 08 ff d0 90 00 } //100
	condition:
		((#a_00_0  & 1)*100+(#a_00_1  & 1)*100+(#a_00_2  & 1)*100+(#a_03_3  & 1)*100) >=400
 
}