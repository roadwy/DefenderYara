
rule Trojan_BAT_Injuke_SPZF_MTB{
	meta:
		description = "Trojan:BAT/Injuke.SPZF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 01 00 00 "
		
	strings :
		$a_03_0 = {0a 06 06 6f ?? 00 00 0a 06 6f ?? 00 00 0a 6f ?? 00 00 0a 0b 02 73 50 00 00 0a 0c 08 07 16 73 51 00 00 0a 0d 73 52 00 00 0a 13 04 } //4
	condition:
		((#a_03_0  & 1)*4) >=4
 
}