
rule Trojan_BAT_LummaStealer_NM_MTB{
	meta:
		description = "Trojan:BAT/LummaStealer.NM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 02 00 00 03 00 "
		
	strings :
		$a_03_0 = {28 0b 00 00 06 73 90 01 01 00 00 06 7e 90 01 01 00 00 04 7e 90 01 01 00 00 04 6f 90 01 01 00 00 06 15 7e 90 01 01 00 00 04 16 8f 90 01 01 00 00 01 7e 90 01 01 00 00 04 8e 69 1f 40 12 00 28 0a 00 00 06 90 00 } //03 00 
		$a_03_1 = {26 16 0b 20 88 01 00 00 0c 16 16 7e 90 01 01 00 00 04 08 8f 90 01 01 00 00 01 7e 90 01 01 00 00 04 16 12 01 28 08 00 00 06 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}