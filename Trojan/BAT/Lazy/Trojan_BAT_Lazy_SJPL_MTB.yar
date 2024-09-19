
rule Trojan_BAT_Lazy_SJPL_MTB{
	meta:
		description = "Trojan:BAT/Lazy.SJPL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 "
		
	strings :
		$a_01_0 = {07 09 91 11 07 61 13 1a 11 43 } //2
		$a_01_1 = {07 09 17 58 08 5d 91 13 1b 11 1a 11 1b 59 } //1
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*1) >=3
 
}