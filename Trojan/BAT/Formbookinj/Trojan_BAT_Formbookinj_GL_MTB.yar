
rule Trojan_BAT_Formbookinj_GL_MTB{
	meta:
		description = "Trojan:BAT/Formbookinj.GL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 0a 00 "
		
	strings :
		$a_02_0 = {0a 02 02 8e 69 17 59 91 1f 70 61 0b 02 8e 69 17 58 8d 90 01 04 0c 16 0d 16 13 04 2b 30 00 08 11 04 02 11 04 91 07 61 06 09 91 61 d2 9c 09 03 6f 90 01 04 17 59 fe 01 13 05 11 05 2c 04 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}