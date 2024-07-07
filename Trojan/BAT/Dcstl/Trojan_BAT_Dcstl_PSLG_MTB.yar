
rule Trojan_BAT_Dcstl_PSLG_MTB{
	meta:
		description = "Trojan:BAT/Dcstl.PSLG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {08 18 28 bd 00 00 0a 28 90 01 03 0a 25 26 72 f7 0a 00 70 28 90 01 03 0a 25 26 6f 90 01 03 0a 25 26 0d 28 90 01 03 0a 25 26 72 7a 0b 00 70 28 6c 00 00 0a 25 26 90 00 } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}