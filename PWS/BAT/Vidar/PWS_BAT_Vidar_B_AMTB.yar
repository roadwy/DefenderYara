
rule PWS_BAT_Vidar_B_AMTB{
	meta:
		description = "PWS:BAT/Vidar.B!AMTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 04 00 00 "
		
	strings :
		$a_81_0 = {68 74 74 70 3a 2f 2f 70 67 6d 61 65 61 76 63 2e 62 65 67 65 74 2e 74 65 63 68 } //2 http://pgmaeavc.beget.tech
		$a_81_1 = {41 64 64 2d 4d 70 50 72 65 66 65 72 65 6e 63 65 20 2d 45 78 63 6c 75 73 69 6f 6e 50 61 74 68 } //2 Add-MpPreference -ExclusionPath
		$a_81_2 = {57 65 62 43 6c 69 65 6e 74 } //1 WebClient
		$a_81_3 = {44 6f 77 6e 6c 6f 61 64 46 69 6c 65 } //1 DownloadFile
	condition:
		((#a_81_0  & 1)*2+(#a_81_1  & 1)*2+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1) >=5
 
}