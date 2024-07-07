
rule Trojan_Win32_WingoObfus_AC_MTB{
	meta:
		description = "Trojan:Win32/WingoObfus.AC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {65 73 74 73 6f 66 74 73 65 72 76 69 63 65 2e 64 61 74 } //1 estsoftservice.dat
		$a_01_1 = {72 65 67 20 61 64 64 20 48 4b 43 55 5c 53 6f 66 74 77 61 72 65 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 52 75 6e 20 2f 64 20 22 25 73 22 20 2f 74 20 52 45 47 5f 53 5a 20 2f 76 20 22 25 73 } //1 reg add HKCU\Software\Microsoft\Windows\CurrentVersion\Run /d "%s" /t REG_SZ /v "%s
		$a_01_2 = {64 61 74 2e 65 78 65 2e 67 69 66 2e 68 74 6d 2e 6a 70 67 2e 6d 6a 73 2e 70 64 66 2e 70 6e 67 2e 73 76 67 2e 74 6d 70 2e 74 } //1 dat.exe.gif.htm.jpg.mjs.pdf.png.svg.tmp.t
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}