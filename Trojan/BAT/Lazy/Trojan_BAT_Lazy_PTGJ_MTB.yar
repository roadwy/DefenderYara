
rule Trojan_BAT_Lazy_PTGJ_MTB{
	meta:
		description = "Trojan:BAT/Lazy.PTGJ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {6f 99 00 00 0a 00 02 6f 60 00 00 06 6f 9a 00 00 0a 6f 9b 00 00 0a 00 1b 8d 74 00 00 01 } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}