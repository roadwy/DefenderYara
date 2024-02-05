
rule Trojan_BAT_AysncRat_RE_MTB{
	meta:
		description = "Trojan:BAT/AysncRat.RE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 02 00 00 05 00 "
		
	strings :
		$a_01_0 = {5f 5a fe 0c 14 00 20 14 00 00 00 64 58 fe 0e 14 00 20 c0 01 00 00 fe 0c 12 00 20 ff ff 0f 00 5f 5a fe 0c 12 00 20 14 00 00 00 64 59 } //01 00 
		$a_01_1 = {24 38 35 64 61 39 36 39 39 2d 65 66 66 66 2d 34 34 36 32 2d 39 35 36 37 2d 30 38 63 36 34 36 39 64 61 38 30 36 } //00 00 
	condition:
		any of ($a_*)
 
}