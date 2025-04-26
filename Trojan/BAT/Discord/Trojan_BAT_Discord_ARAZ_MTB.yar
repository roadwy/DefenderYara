
rule Trojan_BAT_Discord_ARAZ_MTB{
	meta:
		description = "Trojan:BAT/Discord.ARAZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {11 05 11 06 91 13 07 09 11 07 61 0d 11 06 17 58 13 06 11 06 11 05 8e 69 32 e6 } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}