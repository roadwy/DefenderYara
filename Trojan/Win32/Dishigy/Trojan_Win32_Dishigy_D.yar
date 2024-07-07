
rule Trojan_Win32_Dishigy_D{
	meta:
		description = "Trojan:Win32/Dishigy.D,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_00_0 = {67 6f 6f 67 6c 65 62 6f 74 } //1 googlebot
		$a_00_1 = {40 73 6f 6d 65 77 68 65 72 65 } //1 @somewhere
		$a_02_2 = {26 73 79 6e 61 66 70 63 00 90 02 30 24 73 79 6e 61 69 70 00 90 00 } //1
		$a_01_3 = {8b 41 01 80 39 e9 74 0c 80 39 eb 75 0c 0f be c0 41 41 eb 03 83 c1 05 01 c1 } //1
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_02_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}