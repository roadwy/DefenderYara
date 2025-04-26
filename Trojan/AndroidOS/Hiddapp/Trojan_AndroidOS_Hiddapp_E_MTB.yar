
rule Trojan_AndroidOS_Hiddapp_E_MTB{
	meta:
		description = "Trojan:AndroidOS/Hiddapp.E!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {58 2f 47 6f 64 2f 58 2f 6d 61 69 6e } //1 X/God/X/main
		$a_01_1 = {42 41 4e 4b 53 4d 53 2e 74 78 74 } //1 BANKSMS.txt
		$a_01_2 = {41 6b 75 6d 61 53 63 72 65 65 6e 53 68 6f 74 2e 6a 70 67 } //1 AkumaScreenShot.jpg
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}