
rule Trojan_BAT_Lazy_SPCX_MTB{
	meta:
		description = "Trojan:BAT/Lazy.SPCX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 01 00 00 "
		
	strings :
		$a_03_0 = {11 05 11 0a 11 05 6f ?? ?? ?? 0a 5d 6f ?? ?? ?? 0a 11 06 58 11 07 5d 13 0b 11 08 02 11 0a 6f ?? ?? ?? 0a 11 0b 61 d1 6f ?? ?? ?? 0a 26 00 11 0a 17 58 13 0a } //4
	condition:
		((#a_03_0  & 1)*4) >=4
 
}