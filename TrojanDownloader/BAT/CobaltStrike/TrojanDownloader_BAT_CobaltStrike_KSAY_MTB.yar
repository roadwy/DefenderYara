
rule TrojanDownloader_BAT_CobaltStrike_KSAY_MTB{
	meta:
		description = "TrojanDownloader:BAT/CobaltStrike.KSAY!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {4e 4c 63 30 4d 44 67 39 7a 50 36 56 54 76 52 4d 62 66 66 46 30 4f 32 33 57 67 58 62 42 5a 42 6c 33 50 4f 39 2f 31 34 2b 41 42 51 3d } //1 NLc0MDg9zP6VTvRMbffF0O23WgXbBZBl3PO9/14+ABQ=
		$a_81_1 = {61 74 6b 73 2e 65 78 65 } //1 atks.exe
	condition:
		((#a_01_0  & 1)*1+(#a_81_1  & 1)*1) >=2
 
}