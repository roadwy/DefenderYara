
rule Trojan_Win32_AveMaria_CA_MTB{
	meta:
		description = "Trojan:Win32/AveMaria.CA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 02 00 00 "
		
	strings :
		$a_03_0 = {8b c1 83 e0 03 8a 44 05 f4 30 81 90 02 04 41 81 f9 05 5a 00 00 72 e8 90 00 } //2
		$a_01_1 = {6b 57 79 39 6e 63 72 79 70 74 69 6f 6e } //2 kWy9ncryption
	condition:
		((#a_03_0  & 1)*2+(#a_01_1  & 1)*2) >=4
 
}