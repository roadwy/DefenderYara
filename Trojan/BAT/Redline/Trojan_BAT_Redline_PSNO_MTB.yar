
rule Trojan_BAT_Redline_PSNO_MTB{
	meta:
		description = "Trojan:BAT/Redline.PSNO!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {6f 14 00 00 0a 58 0d 09 1a 32 ee 7e 15 00 00 0a 2d 08 08 16 1a 28 16 00 00 0a 08 16 28 17 00 00 0a 13 04 11 04 8d 1d 00 00 01 25 17 73 18 00 00 0a 13 05 06 6f 19 00 00 0a } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}