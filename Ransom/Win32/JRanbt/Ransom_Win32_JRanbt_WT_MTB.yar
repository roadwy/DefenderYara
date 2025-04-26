
rule Ransom_Win32_JRanbt_WT_MTB{
	meta:
		description = "Ransom:Win32/JRanbt.WT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_81_0 = {3a 5c 57 69 6e 64 6f 77 73 5c 4a 52 61 6e 73 6f 6d 42 6f 6f 74 53 63 72 65 65 6e 2e 65 78 65 } //1 :\Windows\JRansomBootScreen.exe
		$a_81_1 = {74 61 73 6b 6d 67 72 2e 65 78 65 2c 63 6d 64 2e 65 78 65 2c 63 68 72 6f 6d 65 2e 65 78 65 2c 66 69 72 65 66 6f 78 2e 65 78 65 2c 6f 70 65 72 61 2e 65 78 65 2c 6d 69 63 72 6f 73 6f 66 74 65 64 67 65 2e 65 78 65 2c 6d 69 63 72 6f 73 6f 66 74 65 64 67 65 63 70 2e 65 78 65 2c 6e 6f 74 65 70 61 64 2b 2b 2c 6e 6f 74 65 70 61 64 2e 65 78 65 2c 69 65 78 70 6c 6f 72 65 2e 65 78 65 } //1 taskmgr.exe,cmd.exe,chrome.exe,firefox.exe,opera.exe,microsoftedge.exe,microsoftedgecp.exe,notepad++,notepad.exe,iexplore.exe
		$a_81_2 = {6a 61 65 6d 69 6e 31 35 30 38 40 6e 61 76 65 72 2e 63 6f 6d } //1 jaemin1508@naver.com
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1) >=3
 
}