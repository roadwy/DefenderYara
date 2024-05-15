
rule Trojan_BAT_ZgRAT_SGA_MTB{
	meta:
		description = "Trojan:BAT/ZgRAT.SGA!MTB,SIGNATURE_TYPE_PEHSTR,02 00 02 00 01 00 00 02 00 "
		
	strings :
		$a_01_0 = {28 aa 05 00 06 0a 06 28 41 00 00 2b 28 42 00 00 2b 0a de 03 } //00 00 
	condition:
		any of ($a_*)
 
}