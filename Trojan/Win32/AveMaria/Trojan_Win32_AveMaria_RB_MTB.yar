
rule Trojan_Win32_AveMaria_RB_MTB{
	meta:
		description = "Trojan:Win32/AveMaria.RB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {8b 45 80 03 45 90 0f be 08 8b 95 60 ff ff ff 0f be 44 15 98 33 c8 8b 55 80 03 55 90 88 0a eb b3 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}