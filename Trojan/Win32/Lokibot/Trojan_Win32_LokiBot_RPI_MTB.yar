
rule Trojan_Win32_LokiBot_RPI_MTB{
	meta:
		description = "Trojan:Win32/LokiBot.RPI!MTB,SIGNATURE_TYPE_PEHSTR,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_01_0 = {90 8b 45 f4 8a 80 04 5e 45 00 8b 55 f0 88 02 90 90 } //00 00 
	condition:
		any of ($a_*)
 
}