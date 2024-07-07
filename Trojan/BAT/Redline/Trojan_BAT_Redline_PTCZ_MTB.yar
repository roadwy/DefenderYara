
rule Trojan_BAT_Redline_PTCZ_MTB{
	meta:
		description = "Trojan:BAT/Redline.PTCZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {6f 40 00 00 0a 28 90 01 01 00 00 0a 28 90 01 01 00 00 0a 03 6f 42 00 00 0a 16 03 6f 43 00 00 0a 28 90 01 01 00 00 0a 6f 45 00 00 0a 90 00 } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}