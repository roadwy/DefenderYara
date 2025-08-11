
rule Trojan_BAT_LummaStealer_MMR_MTB{
	meta:
		description = "Trojan:BAT/LummaStealer.MMR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {09 07 6f 9b 01 00 0a 00 09 07 6f 9c 01 00 0a 00 09 19 6f 9d 01 00 0a 00 09 6f 9e 01 00 0a 13 07 73 9f 01 00 0a 13 04 11 04 11 07 17 73 a0 01 00 0a } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}