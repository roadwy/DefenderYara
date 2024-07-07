
rule Trojan_BAT_Nanocore_NR_MTB{
	meta:
		description = "Trojan:BAT/Nanocore.NR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 02 00 00 "
		
	strings :
		$a_03_0 = {5a 20 81 31 b5 b5 61 38 90 01 03 ff 02 7b 90 01 03 04 28 90 01 03 06 07 20 90 01 03 c8 5a 20 90 01 03 35 61 38 90 01 03 ff 90 00 } //5
		$a_01_1 = {42 42 4e 4d 4b 38 37 33 } //1 BBNMK873
	condition:
		((#a_03_0  & 1)*5+(#a_01_1  & 1)*1) >=6
 
}