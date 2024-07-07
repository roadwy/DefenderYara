
rule Trojan_BAT_DarkTortilla_PSNP_MTB{
	meta:
		description = "Trojan:BAT/DarkTortilla.PSNP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {16 2b f9 28 50 01 00 06 28 90 01 03 0a 0c 06 75 02 00 00 1b 16 9a 28 90 01 03 0a 06 75 02 00 00 1b 17 9a 17 90 00 } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}