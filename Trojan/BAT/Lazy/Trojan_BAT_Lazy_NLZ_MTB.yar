
rule Trojan_BAT_Lazy_NLZ_MTB{
	meta:
		description = "Trojan:BAT/Lazy.NLZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 02 00 00 "
		
	strings :
		$a_03_0 = {28 0f 00 00 0a 72 90 01 01 00 00 70 28 90 01 01 00 00 06 6f 90 01 01 00 00 0a 28 90 01 01 00 00 0a 1e 39 90 01 01 00 00 00 38 90 01 01 00 00 00 26 38 90 01 01 00 00 00 fe 0c 03 00 90 00 } //5
		$a_01_1 = {43 70 70 76 70 } //1 Cppvp
	condition:
		((#a_03_0  & 1)*5+(#a_01_1  & 1)*1) >=6
 
}