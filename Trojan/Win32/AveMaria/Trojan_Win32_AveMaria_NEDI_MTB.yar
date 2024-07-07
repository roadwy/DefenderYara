
rule Trojan_Win32_AveMaria_NEDI_MTB{
	meta:
		description = "Trojan:Win32/AveMaria.NEDI!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0f 00 0f 00 02 00 00 "
		
	strings :
		$a_01_0 = {83 65 0c 00 8b c6 c1 e0 04 03 45 e4 33 45 08 33 c2 2b f8 8b 45 e0 01 45 0c 29 45 fc ff 4d f4 0f 85 6e ff ff ff } //10
		$a_01_1 = {8b 01 89 45 08 8b 45 0c 01 45 08 8b 45 08 89 01 5d } //5
	condition:
		((#a_01_0  & 1)*10+(#a_01_1  & 1)*5) >=15
 
}