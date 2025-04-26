
rule TrojanDownloader_Win32_Agent_XD{
	meta:
		description = "TrojanDownloader:Win32/Agent.XD,SIGNATURE_TYPE_PEHSTR,07 00 06 00 06 00 00 "
		
	strings :
		$a_01_0 = {95 8b 45 3c 8b 44 05 78 8d 74 05 18 ad 91 ad 50 ad 01 e8 92 ad 01 e8 } //2
		$a_01_1 = {c1 c2 03 32 10 40 80 38 00 75 f5 } //2
		$a_01_2 = {69 63 72 6f 73 6f 66 74 5c 41 63 74 69 76 65 20 53 65 74 75 70 5c 49 6e 73 74 61 6c 6c 65 64 } //1 icrosoft\Active Setup\Installed
		$a_01_3 = {6d 73 76 72 68 6f 73 74 } //1 msvrhost
		$a_01_4 = {73 68 65 6c 6c 5f 74 72 61 79 77 6e 64 } //1 shell_traywnd
		$a_01_5 = {2e 53 50 49 52 49 54 } //1 .SPIRIT
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=6
 
}