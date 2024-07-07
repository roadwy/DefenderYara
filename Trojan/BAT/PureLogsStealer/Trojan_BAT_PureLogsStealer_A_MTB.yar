
rule Trojan_BAT_PureLogsStealer_A_MTB{
	meta:
		description = "Trojan:BAT/PureLogsStealer.A!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 03 00 00 "
		
	strings :
		$a_03_0 = {00 00 70 20 00 01 00 00 14 14 14 6f 90 01 01 00 00 0a 6f 90 01 01 00 00 0a 2a 90 00 } //2
		$a_01_1 = {43 72 65 61 74 65 44 65 63 72 79 70 74 6f 72 } //1 CreateDecryptor
		$a_01_2 = {44 6f 77 6e 6c 6f 61 64 44 61 74 61 } //1 DownloadData
	condition:
		((#a_03_0  & 1)*2+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=4
 
}