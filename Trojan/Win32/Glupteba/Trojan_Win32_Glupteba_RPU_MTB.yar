
rule Trojan_Win32_Glupteba_RPU_MTB{
	meta:
		description = "Trojan:Win32/Glupteba.RPU!MTB,SIGNATURE_TYPE_PEHSTR,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_01_0 = {31 11 4e 81 c1 01 00 00 00 39 d9 75 e9 } //01 00 
		$a_01_1 = {8d 14 10 8b 12 } //00 00 
	condition:
		any of ($a_*)
 
}