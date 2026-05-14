
rule Trojan_Win32_Lazy_LMR_MTB{
	meta:
		description = "Trojan:Win32/Lazy.LMR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,1b 00 1b 00 06 00 00 "
		
	strings :
		$a_01_0 = {8b 4d 10 02 c2 0f b6 c0 8a 84 05 00 ff ff ff 32 04 39 88 07 47 83 6d 14 01 } //10
		$a_81_1 = {53 45 4c 45 43 54 20 2a 20 46 52 4f 4d 20 57 69 6e 33 32 5f 50 69 6e 67 53 74 61 74 75 73 20 57 68 65 72 65 20 41 64 64 72 65 73 73 20 3d } //1 SELECT * FROM Win32_PingStatus Where Address =
		$a_81_2 = {63 3a 5c 38 38 38 2e 65 78 65 } //2 c:\888.exe
		$a_81_3 = {6d 79 43 68 72 6f 6d 65 50 61 74 68 3a 25 73 20 6e 6f 74 20 66 6f 75 6e 64 2c 73 74 61 72 74 20 47 65 74 49 6e 73 74 61 6c 6c 50 61 74 68 41 6e 73 69 46 72 6f 6d 52 65 67 } //3 myChromePath:%s not found,start GetInstallPathAnsiFromReg
		$a_81_4 = {53 74 61 72 74 48 69 64 64 65 6e 44 65 73 6b 74 6f 70 3a 48 6f 73 74 3a 25 73 20 50 6f 72 74 3a 25 64 20 43 6f 6e 6e 69 64 3a 25 64 20 44 65 73 6b 74 6f 70 4e 61 6d 65 3a 25 73 } //5 StartHiddenDesktop:Host:%s Port:%d Connid:%d DesktopName:%s
		$a_81_5 = {5b 63 68 72 6f 6d 65 2e 74 78 74 5d 20 73 63 75 63 65 73 73 66 75 6c } //6 [chrome.txt] scucessful
	condition:
		((#a_01_0  & 1)*10+(#a_81_1  & 1)*1+(#a_81_2  & 1)*2+(#a_81_3  & 1)*3+(#a_81_4  & 1)*5+(#a_81_5  & 1)*6) >=27
 
}