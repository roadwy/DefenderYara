
rule Trojan_Win32_Formbook_RPB_MTB{
	meta:
		description = "Trojan:Win32/Formbook.RPB!MTB,SIGNATURE_TYPE_PEHSTR,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {8a 04 39 2c 59 34 4e 2c 6c 34 8d fe c0 34 d6 2c 1c 88 04 39 41 3b cb 72 e7 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}