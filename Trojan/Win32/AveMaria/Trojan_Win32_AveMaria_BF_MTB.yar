
rule Trojan_Win32_AveMaria_BF_MTB{
	meta:
		description = "Trojan:Win32/AveMaria.BF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 02 00 00 "
		
	strings :
		$a_01_0 = {a4 23 66 4c c0 62 73 0b 42 8e dc 29 2f 51 2a 5c 99 3a 4f ad 33 99 66 cf 11 b7 0c 00 aa } //2
		$a_01_1 = {2b a4 d8 52 2f 59 ca 49 9f 14 38 42 51 34 8f 7b } //2
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2) >=4
 
}