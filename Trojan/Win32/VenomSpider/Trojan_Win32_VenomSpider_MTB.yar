
rule Trojan_Win32_VenomSpider_MTB{
	meta:
		description = "Trojan:Win32/VenomSpider!MTB,SIGNATURE_TYPE_PEHSTR,0a 00 0a 00 03 00 00 08 00 "
		
	strings :
		$a_01_0 = {8b 45 08 8b 4d 0c 8b 11 89 10 8b 45 08 83 c0 04 89 45 08 8b 4d 0c 83 c1 04 89 4d 0c 8b 55 10 83 ea 02 89 55 10 } //01 00 
		$a_01_1 = {46 69 6c 65 53 65 65 6b 31 36 } //01 00 
		$a_01_2 = {46 69 6c 65 49 6e 69 74 } //00 00 
	condition:
		any of ($a_*)
 
}