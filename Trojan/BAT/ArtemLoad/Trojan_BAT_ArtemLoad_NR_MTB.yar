
rule Trojan_BAT_ArtemLoad_NR_MTB{
	meta:
		description = "Trojan:BAT/ArtemLoad.NR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {50 72 6f 66 69 6c 65 73 20 4d 61 6e 61 67 65 72 20 76 65 72 73 73 69 6f 6e 20 62 61 63 6b 75 70 20 61 6c 6c } //1 Profiles Manager verssion backup all
		$a_01_1 = {42 72 6f 77 73 65 72 73 4d 61 6e 61 67 65 72 44 61 74 61 53 65 74 54 61 62 6c 65 41 64 61 70 74 65 72 73 } //1 BrowsersManagerDataSetTableAdapters
		$a_01_2 = {4d 6f 72 61 64 20 44 45 52 48 4f 55 52 48 49 } //1 Morad DERHOURHI
		$a_01_3 = {50 72 6f 66 69 6c 73 4d 61 6e 61 67 65 72 47 6d 61 69 6c 2e 50 72 6f 70 65 72 74 69 65 73 2e 52 65 73 6f 75 72 63 65 73 2e 72 65 73 6f 75 72 63 65 73 } //1 ProfilsManagerGmail.Properties.Resources.resources
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}