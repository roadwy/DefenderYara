
rule TrojanDownloader_BAT_PurelogStealer_RFAK_MTB{
	meta:
		description = "TrojanDownloader:BAT/PurelogStealer.RFAK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_81_0 = {54 69 38 54 6f 31 6a 74 67 74 50 62 30 38 68 59 4a 74 4b 7a 37 67 3d 3d } //1 Ti8To1jtgtPb08hYJtKz7g==
		$a_81_1 = {6d 57 63 73 79 74 4c 59 6a 66 38 3d } //1 mWcsytLYjf8=
		$a_81_2 = {68 74 74 70 3a 2f 2f 34 36 2e 38 2e 32 33 37 2e 36 36 2f 73 70 6f 6f 6c 30 32 2f 4f 64 67 63 67 6f 65 7a 2e 77 61 76 } //1 http://46.8.237.66/spool02/Odgcgoez.wav
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1) >=3
 
}