
rule Trojan_AndroidOS_Anatsa_A{
	meta:
		description = "Trojan:AndroidOS/Anatsa.A,SIGNATURE_TYPE_DEXHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_00_0 = {46 6f 6f 6c 69 73 68 55 70 64 61 74 65 53 65 72 76 69 63 65 } //01 00  FoolishUpdateService
		$a_00_1 = {41 70 6b 44 6f 77 6e 6c 6f 61 64 65 72 49 6d 70 6c } //01 00  ApkDownloaderImpl
		$a_00_2 = {75 70 64 61 74 65 5f 63 61 6d 65 } //01 00  update_came
		$a_00_3 = {31 2e 61 70 6b } //00 00  1.apk
	condition:
		any of ($a_*)
 
}