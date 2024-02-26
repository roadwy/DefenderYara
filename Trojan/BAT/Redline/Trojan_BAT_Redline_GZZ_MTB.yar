
rule Trojan_BAT_Redline_GZZ_MTB{
	meta:
		description = "Trojan:BAT/Redline.GZZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 0a 00 "
		
	strings :
		$a_01_0 = {06 09 11 07 9c 06 08 91 06 09 91 58 20 00 01 00 00 5d 13 08 02 11 06 8f 1c 00 00 01 25 71 1c 00 00 01 06 11 08 91 61 d2 } //00 00 
	condition:
		any of ($a_*)
 
}