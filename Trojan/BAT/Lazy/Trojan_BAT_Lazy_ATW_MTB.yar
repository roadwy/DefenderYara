
rule Trojan_BAT_Lazy_ATW_MTB{
	meta:
		description = "Trojan:BAT/Lazy.ATW!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 01 00 00 "
		
	strings :
		$a_01_0 = {09 6f 1d 00 00 06 6f 58 00 00 0a 28 59 00 00 0a 11 05 28 19 00 00 06 2c 0c 06 09 6f 1b 00 00 06 6f 06 00 00 06 09 6f 1f 00 00 06 18 40 8d 00 00 00 11 04 09 6f 1d 00 00 06 6f 58 00 00 0a 07 28 18 00 00 06 09 6f 1d 00 00 06 17 } //3
	condition:
		((#a_01_0  & 1)*3) >=3
 
}