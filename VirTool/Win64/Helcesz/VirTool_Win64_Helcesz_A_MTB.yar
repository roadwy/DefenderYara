
rule VirTool_Win64_Helcesz_A_MTB{
	meta:
		description = "VirTool:Win64/Helcesz.A!MTB,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 08 00 00 "
		
	strings :
		$a_01_0 = {74 65 6c 65 67 72 61 6d 2d 62 6f 74 2d 61 70 69 2e 43 68 61 74 } //1 telegram-bot-api.Chat
		$a_01_1 = {2e 52 53 68 65 6c 6c } //1 .RShell
		$a_01_2 = {2e 52 65 67 69 73 74 72 79 4d 65 74 68 6f 64 } //1 .RegistryMethod
		$a_01_3 = {47 65 6f 49 50 } //1 GeoIP
		$a_01_4 = {47 65 74 43 6c 69 70 62 6f 61 72 64 } //1 GetClipboard
		$a_01_5 = {43 61 70 74 75 72 65 53 63 72 65 65 6e } //1 CaptureScreen
		$a_01_6 = {2e 4e 65 77 44 6f 63 75 6d 65 6e 74 55 70 6c 6f 61 64 } //1 .NewDocumentUpload
		$a_01_7 = {2e 43 6f 6f 6b 69 65 73 } //1 .Cookies
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1) >=8
 
}