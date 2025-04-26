
rule Trojan_Win32_Pascimz_A{
	meta:
		description = "Trojan:Win32/Pascimz.A,SIGNATURE_TYPE_PEHSTR,0b 00 0b 00 04 00 00 "
		
	strings :
		$a_01_0 = {20 00 41 00 64 00 75 00 6c 00 74 00 20 00 50 00 44 00 46 00 20 00 50 00 61 00 73 00 73 00 77 00 6f 00 72 00 64 00 20 00 52 00 } //5  Adult PDF Password R
		$a_01_1 = {75 00 6d 00 62 00 65 00 72 00 20 00 3a 00 00 00 00 00 00 00 00 08 80 50 00 00 00 00 0e 00 2f 00 } //5
		$a_01_2 = {68 74 74 70 3a 2f 2f 77 77 77 2e 63 69 6d 2e 7a 6f 72 2e 6f 72 67 } //1 http://www.cim.zor.org
		$a_01_3 = {00 1c 1c 18 52 47 47 1f 1f 1f 46 0b 01 05 46 12 07 1a 46 07 1a 0f 47 68 } //1
	condition:
		((#a_01_0  & 1)*5+(#a_01_1  & 1)*5+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=11
 
}