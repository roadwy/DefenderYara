
rule Trojan_BAT_NjRat_NEBM_MTB{
	meta:
		description = "Trojan:BAT/NjRat.NEBM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_01_0 = {7e 0e 00 00 04 28 0c 00 00 06 28 62 00 00 0a 0a 28 63 00 00 0a 06 6f 64 00 00 0a 0b 07 6f 65 00 00 0a 0c 08 14 14 6f 61 00 00 0a 26 2a } //10
	condition:
		((#a_01_0  & 1)*10) >=10
 
}