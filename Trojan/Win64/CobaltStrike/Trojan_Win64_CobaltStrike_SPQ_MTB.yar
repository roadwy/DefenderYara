
rule Trojan_Win64_CobaltStrike_SPQ_MTB{
	meta:
		description = "Trojan:Win64/CobaltStrike.SPQ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 02 00 00 02 00 "
		
	strings :
		$a_03_0 = {33 db ba 07 00 00 00 48 8b 0d 90 01 04 ff 15 90 01 04 ff c3 81 fb 7b 03 00 00 72 e4 80 34 3e 05 ba 07 00 00 00 48 8b 0d 90 01 04 ff 15 90 01 04 48 ff c6 48 81 fe 7b 03 00 00 72 90 00 } //02 00 
		$a_03_1 = {ba 7b 03 00 00 33 c9 44 8d 49 40 41 b8 00 10 00 00 ff 15 90 01 04 48 8b d8 48 85 c0 75 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}