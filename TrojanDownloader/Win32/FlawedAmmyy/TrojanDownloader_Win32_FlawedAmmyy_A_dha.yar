
rule TrojanDownloader_Win32_FlawedAmmyy_A_dha{
	meta:
		description = "TrojanDownloader:Win32/FlawedAmmyy.A!dha,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_00_0 = {4d 00 69 00 63 00 72 00 6f 00 73 00 6f 00 66 00 74 00 20 00 53 00 79 00 73 00 74 00 65 00 6d 00 20 00 50 00 72 00 6f 00 74 00 65 00 63 00 74 00 } //1 Microsoft System Protect
		$a_00_1 = {2f 00 43 00 20 00 6e 00 65 00 74 00 2e 00 65 00 78 00 65 00 20 00 73 00 74 00 6f 00 70 00 20 00 66 00 6f 00 75 00 6e 00 64 00 61 00 74 00 69 00 6f 00 6e 00 } //1 /C net.exe stop foundation
		$a_00_2 = {25 73 5c 41 4d 4d 59 59 5c 77 6d 69 68 6f 73 74 2e 65 78 65 } //1 %s\AMMYY\wmihost.exe
		$a_02_3 = {68 74 74 70 3a 2f 2f 90 02 20 2f 64 61 74 65 90 00 } //1
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_02_3  & 1)*1) >=4
 
}