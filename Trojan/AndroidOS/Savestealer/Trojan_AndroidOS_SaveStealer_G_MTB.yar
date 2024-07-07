
rule Trojan_AndroidOS_SaveStealer_G_MTB{
	meta:
		description = "Trojan:AndroidOS/SaveStealer.G!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_00_0 = {63 6f 6d 2f 68 65 6c 6c 6f 2f 74 6f 70 66 66 66 77 } //1 com/hello/topfffw
		$a_00_1 = {67 72 6f 77 74 6f 70 69 61 } //1 growtopia
		$a_00_2 = {77 65 62 68 6f 6f 6b 75 72 6c } //1 webhookurl
		$a_00_3 = {73 61 76 65 64 61 74 } //1 savedat
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1) >=4
 
}