
rule Trojan_BAT_Injuke_TFAA_MTB{
	meta:
		description = "Trojan:BAT/Injuke.TFAA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {16 2d e3 16 2d 02 2b 1d 2b 66 07 08 18 6f ?? 00 00 0a 1f 10 28 ?? 00 00 0a 6f ?? 00 00 0a 08 18 25 2c 0c 58 0c 08 16 2d d2 07 6f ?? 00 00 0a 15 2c ee 32 d4 06 2a } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}