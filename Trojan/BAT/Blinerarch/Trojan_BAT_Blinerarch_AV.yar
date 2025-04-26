
rule Trojan_BAT_Blinerarch_AV{
	meta:
		description = "Trojan:BAT/Blinerarch.AV,SIGNATURE_TYPE_PEHSTR,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {63 43 6f 75 6e 74 72 69 65 73 5f 53 65 6c 65 63 74 65 64 49 6e 64 65 78 43 68 61 6e 67 65 64 } //1 cCountries_SelectedIndexChanged
		$a_01_1 = {73 6d 73 5f 70 61 74 74 65 72 6e } //1 sms_pattern
		$a_01_2 = {75 6b 72 5f 6d 61 73 6b } //1 ukr_mask
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}