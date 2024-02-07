
rule Trojan_Win32_Startpage_EW{
	meta:
		description = "Trojan:Win32/Startpage.EW,SIGNATURE_TYPE_PEHSTR,05 00 05 00 05 00 00 01 00 "
		
	strings :
		$a_01_0 = {65 00 78 00 70 00 6c 00 6f 00 72 00 65 00 72 00 2e 00 65 00 78 00 65 00 2c 00 43 00 3a 00 5c 00 57 00 49 00 4e 00 44 00 4f 00 57 00 53 00 5c 00 73 00 79 00 73 00 74 00 65 00 6d 00 33 00 32 00 5c 00 57 00 69 00 6e 00 6c 00 61 00 6e 00 73 00 2e 00 65 00 78 00 65 00 } //01 00  explorer.exe,C:\WINDOWS\system32\Winlans.exe
		$a_01_1 = {3a 00 72 00 65 00 64 00 65 00 6c 00 } //01 00  :redel
		$a_01_2 = {67 00 6f 00 74 00 6f 00 20 00 72 00 65 00 64 00 65 00 6c 00 } //01 00  goto redel
		$a_01_3 = {64 00 65 00 6c 00 20 00 25 00 30 00 } //01 00  del %0
		$a_01_4 = {48 00 4b 00 43 00 52 00 5c 00 6c 00 61 00 6e 00 72 00 65 00 6e 00 5c 00 74 00 69 00 68 00 75 00 61 00 6e 00 } //00 00  HKCR\lanren\tihuan
	condition:
		any of ($a_*)
 
}