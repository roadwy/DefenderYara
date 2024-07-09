
rule TrojanDownloader_Win32_Agent_XG{
	meta:
		description = "TrojanDownloader:Win32/Agent.XG,SIGNATURE_TYPE_PEHSTR_EXT,05 00 04 00 05 00 00 "
		
	strings :
		$a_02_0 = {5c 62 6f 74 6e 65 74 ?? 2e 64 6c 6c } //1
		$a_00_1 = {42 6f 74 4e 65 74 2f 30 2e 31 20 28 63 6f 6d 70 61 74 69 62 6c 65 29 } //1 BotNet/0.1 (compatible)
		$a_00_2 = {2f 62 6f 74 6e 65 74 2f 62 68 6f 2e 64 6c 6c } //1 /botnet/bho.dll
		$a_00_3 = {68 74 74 70 3a 2f 2f 36 37 2e } //1 http://67.
		$a_00_4 = {62 6f 74 6e 65 74 2f 6c 6f 61 64 65 72 2e 6a 73 70 } //1 botnet/loader.jsp
	condition:
		((#a_02_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1) >=4
 
}