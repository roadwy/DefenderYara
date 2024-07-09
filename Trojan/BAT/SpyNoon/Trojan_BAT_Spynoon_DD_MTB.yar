
rule Trojan_BAT_Spynoon_DD_MTB{
	meta:
		description = "Trojan:BAT/Spynoon.DD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 04 00 00 "
		
	strings :
		$a_03_0 = {0a 16 0b 2b 16 02 07 8f ?? 00 00 01 25 47 06 07 1f 10 5d 91 61 d2 52 07 17 58 0b 07 02 8e 69 fe 04 0c 08 2d e0 } //2
		$a_01_1 = {41 70 70 65 6e 64 } //1 Append
		$a_01_2 = {47 65 74 42 79 74 65 73 } //1 GetBytes
		$a_01_3 = {57 69 6e 64 6f 77 73 46 6f 72 6d 73 41 70 70 31 2e 50 72 6f 70 65 72 74 69 65 73 2e 52 65 73 6f 75 72 63 65 73 } //1 WindowsFormsApp1.Properties.Resources
	condition:
		((#a_03_0  & 1)*2+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=5
 
}