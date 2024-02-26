
rule Trojan_BAT_Injuke_AAQJ_MTB{
	meta:
		description = "Trojan:BAT/Injuke.AAQJ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 02 00 "
		
	strings :
		$a_01_0 = {54 6d 78 75 79 77 74 69 61 70 64 2e 50 72 6f 70 65 72 74 69 65 73 2e 52 65 73 6f 75 72 63 65 73 2e 72 65 73 6f 75 72 63 65 73 } //01 00  Tmxuywtiapd.Properties.Resources.resources
		$a_01_1 = {63 64 31 63 39 33 35 35 2d 38 31 65 36 2d 34 34 33 36 2d 39 35 30 63 2d 36 65 36 33 35 37 33 35 61 62 38 35 } //00 00  cd1c9355-81e6-4436-950c-6e635735ab85
	condition:
		any of ($a_*)
 
}