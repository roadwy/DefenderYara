
rule Trojan_BAT_Lazy_PTJY_MTB{
	meta:
		description = "Trojan:BAT/Lazy.PTJY!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {73 d9 03 00 0a 20 e3 cd 33 8f 28 ?? 00 00 06 28 ?? 03 00 0a 0a 06 28 ?? 03 00 0a 02 06 28 ?? 03 00 0a 7d e2 01 00 04 de 03 } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}