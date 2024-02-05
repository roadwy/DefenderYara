
rule Trojan_BAT_Redlinestealer_YKUF_MTB{
	meta:
		description = "Trojan:BAT/Redlinestealer.YKUF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_01_0 = {07 25 17 59 } //01 00 
		$a_03_1 = {2d 0d 26 16 2d cb 16 fe 02 0c 08 2d d9 2b 03 0b 2b f1 06 6f 90 01 03 0a 28 90 01 03 2b 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}