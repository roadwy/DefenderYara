
rule Trojan_Win32_CoinMiner_DA_MTB{
	meta:
		description = "Trojan:Win32/CoinMiner.DA!MTB,SIGNATURE_TYPE_PEHSTR,0d 00 0d 00 0e 00 00 "
		
	strings :
		$a_01_0 = {73 65 72 62 61 31 32 73 68 65 } //1 serba12she
		$a_01_1 = {74 61 73 6b 6b 69 6c 6c 20 2f 69 6d 20 77 73 63 72 69 70 74 2e 65 78 65 20 2f 66 } //1 taskkill /im wscript.exe /f
		$a_01_2 = {5c 74 61 6f 2e 76 62 73 } //1 \tao.vbs
		$a_01_3 = {5c 6c 73 2e 76 62 73 } //1 \ls.vbs
		$a_01_4 = {57 73 63 72 69 70 74 2e 43 72 65 61 74 65 4f 62 6a 65 63 74 28 22 57 73 63 72 69 70 74 2e 53 68 65 6c 6c 22 29 } //1 Wscript.CreateObject("Wscript.Shell")
		$a_01_5 = {57 73 68 53 68 65 6c 6c 2e 52 75 6e } //1 WshShell.Run
		$a_01_6 = {63 68 72 6f 6d 65 61 2e 65 78 65 } //1 chromea.exe
		$a_01_7 = {63 68 72 6f 6d 65 73 2e 65 78 65 } //1 chromes.exe
		$a_01_8 = {63 72 79 70 74 6f 6e 69 67 68 74 } //1 cryptonight
		$a_01_9 = {2d 2d 64 6f 6e 61 74 65 2d 6c 65 76 65 6c } //1 --donate-level
		$a_01_10 = {73 74 72 61 74 75 6d 2b 74 63 70 } //1 stratum+tcp
		$a_01_11 = {5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 50 6f 6c 69 63 69 65 73 5c 45 78 70 6c 6f 72 65 72 5c 52 75 6e 5c 41 44 53 4c 20 44 69 61 6c } //1 \CurrentVersion\Policies\Explorer\Run\ADSL Dial
		$a_01_12 = {43 3a 5c 73 74 61 72 74 2e 63 6d 64 } //1 C:\start.cmd
		$a_01_13 = {40 74 61 73 6b 6d 67 72 2e 65 78 65 } //1 @taskmgr.exe
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1+(#a_01_8  & 1)*1+(#a_01_9  & 1)*1+(#a_01_10  & 1)*1+(#a_01_11  & 1)*1+(#a_01_12  & 1)*1+(#a_01_13  & 1)*1) >=13
 
}