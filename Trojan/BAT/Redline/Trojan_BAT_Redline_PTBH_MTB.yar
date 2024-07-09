
rule Trojan_BAT_Redline_PTBH_MTB{
	meta:
		description = "Trojan:BAT/Redline.PTBH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {6f 2a 00 00 0a 25 72 83 00 00 70 73 2b 00 00 0a 06 72 0a 01 00 70 28 ?? 00 00 0a 6f 2c 00 00 0a } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}