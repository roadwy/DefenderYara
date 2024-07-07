
rule Trojan_Win32_AveMaria_NER_MTB{
	meta:
		description = "Trojan:Win32/AveMaria.NER!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {33 d2 8b c3 6a 64 5f f7 f7 8a 44 15 98 30 04 0b 43 81 fb 00 e8 03 00 7c e7 } //1
		$a_01_1 = {41 54 4c 43 6f 6e } //1 ATLCon
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}