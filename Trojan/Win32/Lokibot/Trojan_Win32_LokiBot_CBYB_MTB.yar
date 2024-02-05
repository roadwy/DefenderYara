
rule Trojan_Win32_LokiBot_CBYB_MTB{
	meta:
		description = "Trojan:Win32/LokiBot.CBYB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {99 03 04 24 13 54 24 04 83 c4 90 01 01 8b d1 8a 12 80 f2 90 01 01 88 10 ff 06 41 81 3e 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}