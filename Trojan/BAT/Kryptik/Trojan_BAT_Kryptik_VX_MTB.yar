
rule Trojan_BAT_Kryptik_VX_MTB{
	meta:
		description = "Trojan:BAT/Kryptik.VX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0c 00 0c 00 02 00 00 0a 00 "
		
	strings :
		$a_03_0 = {06 02 07 28 90 02 04 25 26 03 07 03 28 90 02 04 25 26 5d 28 90 02 04 25 26 61 d1 28 90 02 04 25 26 26 07 17 58 0b 07 02 28 90 02 04 25 26 90 00 } //02 00 
		$a_80_1 = {46 72 6f 6d 42 61 73 65 36 34 } //FromBase64  00 00 
	condition:
		any of ($a_*)
 
}