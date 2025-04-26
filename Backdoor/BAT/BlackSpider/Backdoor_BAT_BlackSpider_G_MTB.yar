
rule Backdoor_BAT_BlackSpider_G_MTB{
	meta:
		description = "Backdoor:BAT/BlackSpider.G!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 07 00 00 "
		
	strings :
		$a_80_0 = {5c 42 6c 61 63 6b 53 70 69 64 65 72 2e 49 6e 73 74 61 6c 6c 65 72 5c } //\BlackSpider.Installer\  1
		$a_80_1 = {41 6e 74 69 76 69 72 75 73 50 72 6f 64 75 63 74 } //AntivirusProduct  1
		$a_80_2 = {70 61 74 68 54 6f 53 69 67 6e 65 64 50 72 6f 64 75 63 74 45 78 65 } //pathToSignedProductExe  1
		$a_80_3 = {49 50 45 6e 61 62 6c 65 64 20 3d 20 54 52 55 45 } //IPEnabled = TRUE  1
		$a_80_4 = {2f 43 20 59 20 2f 4e 20 2f 44 20 59 20 2f 54 } ///C Y /N /D Y /T  1
		$a_80_5 = {73 63 68 74 61 73 6b 73 2e 65 78 65 } //schtasks.exe  1
		$a_80_6 = {69 70 2d 61 70 69 2e 63 6f 6d 2f 6a 73 6f 6e 2f } //ip-api.com/json/  1
	condition:
		((#a_80_0  & 1)*1+(#a_80_1  & 1)*1+(#a_80_2  & 1)*1+(#a_80_3  & 1)*1+(#a_80_4  & 1)*1+(#a_80_5  & 1)*1+(#a_80_6  & 1)*1) >=7
 
}