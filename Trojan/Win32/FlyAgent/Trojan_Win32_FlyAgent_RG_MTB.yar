
rule Trojan_Win32_FlyAgent_RG_MTB{
	meta:
		description = "Trojan:Win32/FlyAgent.RG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 06 00 00 "
		
	strings :
		$a_01_0 = {4d 69 63 72 6f 73 6f 66 74 5c 56 42 53 33 2e 76 62 73 } //1 Microsoft\VBS3.vbs
		$a_01_1 = {4d 69 63 72 6f 73 6f 66 74 5c 73 76 63 68 63 73 74 2e 65 78 65 } //1 Microsoft\svchcst.exe
		$a_01_2 = {4d 69 63 72 6f 73 6f 66 74 5c 43 6f 6e 66 69 67 2e 69 6e 69 } //1 Microsoft\Config.ini
		$a_01_3 = {63 6d 64 2e 65 78 65 20 2f 63 20 64 65 6c 20 73 76 63 68 63 73 74 2e 65 78 65 } //1 cmd.exe /c del svchcst.exe
		$a_01_4 = {53 74 61 72 74 20 4d 65 6e 75 5c 50 72 6f 67 72 61 6d 73 5c 53 74 61 72 74 75 70 5c 77 69 6e 73 2e 6c 6e 6b } //1 Start Menu\Programs\Startup\wins.lnk
		$a_01_5 = {43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 52 75 6e 5c 33 36 30 73 61 66 6f } //1 CurrentVersion\Run\360safo
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=6
 
}