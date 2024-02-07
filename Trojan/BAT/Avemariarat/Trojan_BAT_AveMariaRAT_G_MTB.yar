
rule Trojan_BAT_AveMariaRAT_G_MTB{
	meta:
		description = "Trojan:BAT/AveMariaRAT.G!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 02 00 00 02 00 "
		
	strings :
		$a_01_0 = {09 11 05 02 11 05 91 11 04 61 08 07 91 61 b4 9c 07 03 6f } //02 00 
		$a_01_1 = {64 00 61 00 73 00 64 00 61 00 73 00 64 00 } //00 00  dasdasd
	condition:
		any of ($a_*)
 
}