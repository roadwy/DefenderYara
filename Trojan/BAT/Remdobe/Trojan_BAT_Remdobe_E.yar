
rule Trojan_BAT_Remdobe_E{
	meta:
		description = "Trojan:BAT/Remdobe.E,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {67 00 6f 00 62 00 6c 00 6d 00 61 00 68 00 33 00 37 00 31 00 7a 00 } //1 goblmah371z
		$a_01_1 = {2d 00 2d 00 6e 00 6f 00 2d 00 73 00 75 00 62 00 6d 00 69 00 74 00 2d 00 73 00 74 00 61 00 6c 00 65 00 } //1 --no-submit-stale
		$a_01_2 = {21 2f 00 43 00 20 00 61 00 74 00 74 00 72 00 69 00 62 00 20 00 2d 00 73 00 20 00 2d 00 68 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}