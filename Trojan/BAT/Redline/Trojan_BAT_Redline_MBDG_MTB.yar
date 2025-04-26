
rule Trojan_BAT_Redline_MBDG_MTB{
	meta:
		description = "Trojan:BAT/Redline.MBDG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {40 00 40 00 40 00 40 00 50 00 30 00 33 00 40 00 50 00 45 00 32 00 40 00 50 00 30 00 33 00 40 00 50 00 45 00 32 00 40 00 50 00 30 00 33 00 40 00 50 00 45 00 32 00 40 00 50 00 31 00 33 00 40 00 40 00 40 00 50 00 45 00 36 00 40 00 50 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}