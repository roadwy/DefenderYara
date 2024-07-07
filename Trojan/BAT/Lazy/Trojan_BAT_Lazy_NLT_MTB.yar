
rule Trojan_BAT_Lazy_NLT_MTB{
	meta:
		description = "Trojan:BAT/Lazy.NLT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 02 00 00 "
		
	strings :
		$a_03_0 = {fe 09 06 00 71 90 01 03 01 fe 90 01 02 00 fe 90 01 02 00 6f 90 01 03 0a fe 90 01 02 00 90 00 } //5
		$a_01_1 = {52 6f 6d 6d 61 6e 79 78 61 6e 74 68 61 6e } //1 Rommanyxanthan
	condition:
		((#a_03_0  & 1)*5+(#a_01_1  & 1)*1) >=6
 
}