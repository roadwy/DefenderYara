
rule Trojan_Win64_Clipbanker_CCHT_MTB{
	meta:
		description = "Trojan:Win64/Clipbanker.CCHT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {33 c9 ff 15 90 01 04 85 c0 0f 84 90 01 04 b9 01 00 00 00 ff 15 90 01 04 48 8b f8 48 8b c8 ff 15 90 01 04 48 8b d8 48 c7 c6 ff ff ff ff 4c 8b c6 49 ff c0 42 80 3c 00 00 75 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}