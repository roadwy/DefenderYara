
rule Trojan_Win32_AveMaria_NEEG_MTB{
	meta:
		description = "Trojan:Win32/AveMaria.NEEG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_01_0 = {89 44 24 10 8b 44 24 28 31 44 24 14 8b 4c 24 10 31 4c 24 14 8b 44 24 18 89 44 24 2c 8b 44 24 14 29 44 24 2c 8b 44 24 2c 89 44 24 18 8d 44 24 30 } //10
	condition:
		((#a_01_0  & 1)*10) >=10
 
}