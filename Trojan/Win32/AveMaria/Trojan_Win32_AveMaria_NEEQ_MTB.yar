
rule Trojan_Win32_AveMaria_NEEQ_MTB{
	meta:
		description = "Trojan:Win32/AveMaria.NEEQ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 0a 00 "
		
	strings :
		$a_03_0 = {89 f0 f7 e1 d1 ea 83 e2 fc 8d 04 52 f7 d8 8a 84 06 5b 2a 90 01 01 00 30 04 33 46 39 f7 75 e3 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}