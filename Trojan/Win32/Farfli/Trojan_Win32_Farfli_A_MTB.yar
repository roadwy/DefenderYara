
rule Trojan_Win32_Farfli_A_MTB{
	meta:
		description = "Trojan:Win32/Farfli.A!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 04 00 00 "
		
	strings :
		$a_03_0 = {55 8b ce e8 ?? ?? ?? ?? 8b e8 85 ed ?? ?? 8b 46 04 55 50 53 ?? ?? ?? ?? ?? ?? 83 c4 0c 8b 46 04 85 c0 } //2
		$a_01_1 = {53 4f 46 54 57 41 52 45 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 52 75 6e } //1 SOFTWARE\Microsoft\Windows\CurrentVersion\Run
		$a_01_2 = {41 70 70 6c 69 63 61 74 69 6f 6e 73 5c 69 65 78 70 6c 6f 72 65 2e 65 78 65 5c 73 68 65 6c 6c 5c 6f 70 65 6e 5c 63 6f 6d 6d 61 6e 64 } //1 Applications\iexplore.exe\shell\open\command
		$a_00_3 = {6b 69 6e 68 2e 78 6d 63 78 6d 72 2e 63 6f 6d } //2 kinh.xmcxmr.com
	condition:
		((#a_03_0  & 1)*2+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_00_3  & 1)*2) >=6
 
}