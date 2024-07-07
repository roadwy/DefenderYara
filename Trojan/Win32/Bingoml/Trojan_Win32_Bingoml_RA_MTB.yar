
rule Trojan_Win32_Bingoml_RA_MTB{
	meta:
		description = "Trojan:Win32/Bingoml.RA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {8b 4d fc 8b 55 08 0f b7 0c 4a 8b 45 fc 33 d2 be 90 01 01 00 00 00 f7 f6 83 c2 31 33 ca 8b 55 fc 8b 45 f8 66 89 0c 50 90 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}