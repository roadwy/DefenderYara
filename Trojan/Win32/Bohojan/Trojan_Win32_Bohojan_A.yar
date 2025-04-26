
rule Trojan_Win32_Bohojan_A{
	meta:
		description = "Trojan:Win32/Bohojan.A,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {63 3a 5c 61 63 6c 69 65 6e 74 5c 4c 6f 67 2e 74 78 74 } //1 c:\aclient\Log.txt
		$a_01_1 = {42 6f 74 4d 61 69 6e 3a 3a 6f 6e 42 65 66 6f 72 65 4e 61 76 69 67 61 74 65 28 } //1 BotMain::onBeforeNavigate(
		$a_01_2 = {66 6f 72 63 65 5f 68 6f 6d 65 70 61 67 65 } //1 force_homepage
		$a_01_3 = {63 6f 6e 66 69 67 20 64 6f 77 6e 6c 6f 61 64 65 72 } //1 config downloader
		$a_01_4 = {43 61 74 63 68 69 6e 67 20 75 72 6c 20 66 6f 72 20 72 65 64 69 72 65 63 74 69 6f 6e } //1 Catching url for redirection
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}