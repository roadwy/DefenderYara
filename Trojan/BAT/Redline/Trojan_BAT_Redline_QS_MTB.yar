
rule Trojan_BAT_Redline_QS_MTB{
	meta:
		description = "Trojan:BAT/Redline.QS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0c 00 0c 00 03 00 00 0a 00 "
		
	strings :
		$a_01_0 = {11 02 11 03 11 01 11 03 11 01 8e 69 5d 91 11 04 11 03 91 61 d2 9c 20 } //01 00 
		$a_01_1 = {47 65 74 42 79 74 65 73 } //01 00  GetBytes
		$a_01_2 = {44 79 6e 61 6d 69 63 49 6e 76 6f 6b 65 } //00 00  DynamicInvoke
	condition:
		any of ($a_*)
 
}