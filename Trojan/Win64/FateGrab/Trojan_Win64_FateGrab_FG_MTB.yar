
rule Trojan_Win64_FateGrab_FG_MTB{
	meta:
		description = "Trojan:Win64/FateGrab.FG!MTB,SIGNATURE_TYPE_PEHSTR,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_01_0 = {0f b6 0c 0a 33 c1 b9 01 00 00 00 48 6b c9 07 48 8b 54 24 08 0f b6 0c 0a 33 c1 33 44 24 10 } //01 00 
		$a_01_1 = {4d 69 6d 65 53 6f 75 72 63 65 } //00 00  MimeSource
	condition:
		any of ($a_*)
 
}