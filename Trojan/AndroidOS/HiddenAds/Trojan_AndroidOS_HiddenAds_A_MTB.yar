
rule Trojan_AndroidOS_HiddenAds_A_MTB{
	meta:
		description = "Trojan:AndroidOS/HiddenAds.A!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,04 00 04 00 02 00 00 "
		
	strings :
		$a_03_0 = {21 30 23 00 1f 00 12 01 21 32 35 21 0c 00 48 02 03 01 df 02 02 90 01 01 8d 22 4f 02 00 01 d8 01 01 01 28 f4 11 90 00 } //2
		$a_00_1 = {72 65 73 5f 72 61 77 2e 6a 73 } //2 res_raw.js
	condition:
		((#a_03_0  & 1)*2+(#a_00_1  & 1)*2) >=4
 
}