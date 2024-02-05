
rule Trojan_BAT_Spy_KAREGA_MTB{
	meta:
		description = "Trojan:BAT/Spy.KAREGA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 0a 00 "
		
	strings :
		$a_03_0 = {14 0a 1e 8d 44 00 00 01 25 d0 9d 00 00 04 28 90 01 03 0a 0b 73 22 00 00 0a 0c 00 73 23 00 00 0a 0d 00 09 20 00 01 00 00 6f 90 01 03 0a 00 09 20 80 00 00 00 6f 90 01 03 0a 00 28 90 01 03 0a 72 6b 00 00 70 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}