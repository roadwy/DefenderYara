
rule Trojan_BAT_SamuraiStealer_SK_MTB{
	meta:
		description = "Trojan:BAT/SamuraiStealer.SK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 03 00 00 "
		
	strings :
		$a_01_0 = {00 73 d3 01 00 0a 20 05 00 00 00 20 14 00 00 00 6f d5 01 00 0a fe 0e 01 00 fe 0c 01 00 6c 28 34 00 00 0a fe 0e 02 00 } //2
		$a_01_1 = {67 65 74 5f 43 61 72 64 4e 75 6d 62 65 72 } //1 get_CardNumber
		$a_01_2 = {67 65 74 5f 43 6f 6f 6b 69 65 73 } //1 get_Cookies
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=4
 
}