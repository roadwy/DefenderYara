
rule Trojan_Win64_Expiro_RPX_MTB{
	meta:
		description = "Trojan:Win64/Expiro.RPX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {f7 91 cc 00 00 00 f7 91 34 01 00 00 48 81 c6 00 04 00 00 48 81 c1 00 04 00 00 48 81 fe 00 c0 08 00 0f 85 90 01 02 ff ff 59 e8 90 01 02 ff ff 48 8b e5 5d 41 5f 41 5e 41 5d 41 5c 41 5b 41 5a 41 59 41 58 5f 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}