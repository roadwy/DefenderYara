
rule Trojan_BAT_Lazy_PSQR_MTB{
	meta:
		description = "Trojan:BAT/Lazy.PSQR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {07 08 6f 82 00 00 0a 17 73 83 00 00 0a 13 04 11 04 02 16 02 8e 69 6f 84 00 00 0a 11 04 6f 4b 00 00 0a de 0c } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}