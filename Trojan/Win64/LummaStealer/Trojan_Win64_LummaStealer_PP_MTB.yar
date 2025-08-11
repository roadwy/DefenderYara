
rule Trojan_Win64_LummaStealer_PP_MTB{
	meta:
		description = "Trojan:Win64/LummaStealer.PP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 03 00 00 "
		
	strings :
		$a_03_0 = {48 89 8c 24 ?? 00 00 00 48 8d 0d 29 58 15 00 48 89 8c 24 ?? 00 00 00 48 8b 1d aa 99 34 00 48 8d 05 43 74 15 00 48 8d 8c 24 ?? 00 00 00 bf 01 00 00 00 48 89 fe e8 ce 78 eb ff 48 81 c4 28 01 00 00 } //2
		$a_01_1 = {72 65 67 20 61 64 64 20 22 48 4b 43 55 5c 53 6f 66 74 77 61 72 65 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 52 75 6e 22 20 2f 76 20 41 64 6f 62 65 55 70 64 61 74 65 72 20 2f 74 20 52 45 47 5f 53 5a 20 2f 64 20 22 25 73 22 20 2f 66 } //1 reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Run" /v AdobeUpdater /t REG_SZ /d "%s" /f
		$a_01_2 = {63 6d 64 2e 65 78 65 20 2f 63 } //1 cmd.exe /c
	condition:
		((#a_03_0  & 1)*2+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=4
 
}