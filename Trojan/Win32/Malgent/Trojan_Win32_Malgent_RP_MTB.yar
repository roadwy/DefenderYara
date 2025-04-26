
rule Trojan_Win32_Malgent_RP_MTB{
	meta:
		description = "Trojan:Win32/Malgent.RP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,70 00 70 00 04 00 00 "
		
	strings :
		$a_01_0 = {44 4c 4c 5c 74 65 73 74 5c 52 65 6c 65 61 73 65 5c 44 6c 6c 31 2e 70 64 62 } //100 DLL\test\Release\Dll1.pdb
		$a_01_1 = {45 00 6e 00 73 00 75 00 70 00 2e 00 6c 00 6f 00 67 00 } //10 Ensup.log
		$a_01_2 = {53 69 67 6e 61 6c 43 68 72 6f 6d 65 45 6c 66 } //1 SignalChromeElf
		$a_01_3 = {22 43 3a 5c 57 69 6e 64 6f 77 73 5c 69 65 78 70 6c 6f 72 65 2e 65 78 65 22 } //1 "C:\Windows\iexplore.exe"
	condition:
		((#a_01_0  & 1)*100+(#a_01_1  & 1)*10+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=112
 
}
rule Trojan_Win32_Malgent_RP_MTB_2{
	meta:
		description = "Trojan:Win32/Malgent.RP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,ffffffcc 00 ffffffcc 00 06 00 00 "
		
	strings :
		$a_01_0 = {53 69 67 6e 61 6c 43 68 72 6f 6d 65 45 6c 66 } //1 SignalChromeElf
		$a_01_1 = {5c 52 65 6c 65 61 73 65 5c 6d 66 63 2e 70 64 62 } //100 \Release\mfc.pdb
		$a_01_2 = {7a 68 2d 43 4e 2f 4e 55 53 44 61 74 61 2f 4d 32 30 35 32 48 6f 6e 67 79 75 2e 76 6f 69 63 65 41 73 73 69 73 74 61 6e 74 2e 75 6e 74 } //100 zh-CN/NUSData/M2052Hongyu.voiceAssistant.unt
		$a_01_3 = {7a 68 2d 43 4e 2f 4e 55 53 44 61 74 61 2f 4d 32 30 35 32 4b 61 6e 67 6b 61 6e 67 2e 6b 65 79 62 6f 61 72 64 2e 75 6e 74 } //1 zh-CN/NUSData/M2052Kangkang.keyboard.unt
		$a_01_4 = {43 6d 66 63 44 6f 63 } //1 CmfcDoc
		$a_01_5 = {43 6d 66 63 56 69 65 77 } //1 CmfcView
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*100+(#a_01_2  & 1)*100+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=204
 
}