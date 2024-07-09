
rule TrojanDownloader_BAT_Taskun_CCHZ_MTB{
	meta:
		description = "TrojanDownloader:BAT/Taskun.CCHZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {11 02 11 03 11 01 11 03 91 72 2f 00 00 70 ?? 0b 00 00 06 59 d2 9c 20 1e 00 00 00 38 } //1
		$a_01_1 = {38 00 30 00 2e 00 36 00 36 00 2e 00 37 00 35 00 2e 00 34 00 34 00 } //1 80.66.75.44
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}