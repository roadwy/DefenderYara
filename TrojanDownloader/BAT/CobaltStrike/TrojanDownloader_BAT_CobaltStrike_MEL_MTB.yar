
rule TrojanDownloader_BAT_CobaltStrike_MEL_MTB{
	meta:
		description = "TrojanDownloader:BAT/CobaltStrike.MEL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_81_0 = {67 28 27 68 74 74 70 3a 2f 2f 34 37 2e 31 30 36 2e 36 37 2e 31 33 38 3a 38 30 2f 61 27 29 29 } //1 g('http://47.106.67.138:80/a'))
		$a_81_1 = {53 79 73 74 65 6d 2e 4d 61 6e 61 67 65 6d 65 6e 74 2e 41 75 74 6f 6d 61 74 69 6f 6e 2e 41 6d 73 69 55 74 69 6c 73 } //1 System.Management.Automation.AmsiUtils
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1) >=2
 
}