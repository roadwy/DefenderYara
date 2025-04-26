
rule Trojan_Win32_Raccoon_CA_MTB{
	meta:
		description = "Trojan:Win32/Raccoon.CA!MTB,SIGNATURE_TYPE_PEHSTR,0a 00 0a 00 02 00 00 "
		
	strings :
		$a_01_0 = {8d 44 24 20 50 6a 00 ff d6 6a 00 8d 8c 24 50 0c 00 00 51 ff d7 8d 54 24 24 52 ff d3 6a 00 ff d5 6a 00 8d 84 24 50 10 00 00 50 6a 00 6a 00 6a 00 6a 00 } //5
		$a_01_1 = {33 d2 33 c9 8d 44 24 1c 50 66 89 4c 24 1c 66 89 54 24 1e 8b 4c 24 1c } //5
	condition:
		((#a_01_0  & 1)*5+(#a_01_1  & 1)*5) >=10
 
}