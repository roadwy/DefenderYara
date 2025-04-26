
rule TrojanDownloader_BAT_Seraph_PAAM_MTB{
	meta:
		description = "TrojanDownloader:BAT/Seraph.PAAM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {50 00 6f 00 77 00 65 00 72 00 53 00 68 00 65 00 6c 00 6c 00 2e 00 65 00 78 00 65 00 } //1 PowerShell.exe
		$a_01_1 = {5c 00 62 00 66 00 73 00 76 00 63 00 2e 00 65 00 78 00 65 00 } //1 \bfsvc.exe
		$a_01_2 = {2f 2f 53 53 2e 58 46 49 4c 45 53 2e 45 55 2e 4f 52 47 2f 66 61 76 69 63 6f 6e 2e 70 6e 67 } //1 //SS.XFILES.EU.ORG/favicon.png
		$a_01_3 = {2f 00 63 00 20 00 73 00 63 00 68 00 74 00 61 00 73 00 6b 00 73 00 20 00 2f 00 63 00 72 00 65 00 61 00 74 00 65 00 20 00 2f 00 73 00 63 00 20 00 6f 00 6e 00 6c 00 6f 00 67 00 6f 00 6e 00 20 00 2f 00 74 00 6e 00 20 00 43 00 74 00 66 00 6d 00 6f 00 6e 00 20 00 2f 00 74 00 72 00 20 00 43 00 3a 00 5c 00 57 00 69 00 6e 00 64 00 6f 00 77 00 73 00 5c 00 63 00 74 00 66 00 6d 00 6f 00 6e 00 2e 00 65 00 78 00 65 00 } //1 /c schtasks /create /sc onlogon /tn Ctfmon /tr C:\Windows\ctfmon.exe
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}