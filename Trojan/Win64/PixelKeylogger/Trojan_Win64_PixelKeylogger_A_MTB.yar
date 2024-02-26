
rule Trojan_Win64_PixelKeylogger_A_MTB{
	meta:
		description = "Trojan:Win64/PixelKeylogger.A!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 02 00 "
		
	strings :
		$a_03_0 = {8b cb ff 15 90 01 02 00 00 66 0f ba e0 90 01 01 72 90 01 01 ff c3 81 fb 90 01 04 7e 90 01 01 8b 1d 46 45 00 00 eb 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}