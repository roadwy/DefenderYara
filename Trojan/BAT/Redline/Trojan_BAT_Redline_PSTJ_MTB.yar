
rule Trojan_BAT_Redline_PSTJ_MTB{
	meta:
		description = "Trojan:BAT/Redline.PSTJ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 02 00 "
		
	strings :
		$a_01_0 = {73 e1 01 00 06 06 20 e9 24 09 00 28 ce 01 00 06 26 dd 14 00 00 00 02 06 16 9a 79 5a 00 00 02 71 5a 00 00 02 81 5a 00 00 02 dc } //00 00 
	condition:
		any of ($a_*)
 
}