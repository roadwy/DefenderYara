
rule Trojan_Win32_Kechang_SP_MSR{
	meta:
		description = "Trojan:Win32/Kechang.SP!MSR,SIGNATURE_TYPE_PEHSTR,03 00 03 00 05 00 00 "
		
	strings :
		$a_01_0 = {72 65 67 20 61 64 64 20 22 48 4b 43 55 5c 53 6f 66 74 77 61 72 65 5c 4d 69 63 72 6f 73 6f 66 74 5c 49 6e 74 65 72 6e 65 74 20 45 78 70 6c 6f 72 65 72 5c 50 68 69 73 68 69 6e 67 46 69 6c 74 65 72 22 } //1 reg add "HKCU\Software\Microsoft\Internet Explorer\PhishingFilter"
		$a_01_1 = {5c 00 4d 00 69 00 63 00 72 00 6f 00 73 00 6f 00 66 00 74 00 5c 00 57 00 69 00 6e 00 64 00 6f 00 77 00 73 00 5c 00 6d 00 69 00 72 00 72 00 6f 00 72 00 68 00 69 00 } //1 \Microsoft\Windows\mirrorhi
		$a_01_2 = {5c 00 4d 00 69 00 63 00 72 00 6f 00 73 00 6f 00 66 00 74 00 5c 00 57 00 69 00 6e 00 64 00 6f 00 77 00 73 00 5c 00 68 00 64 00 69 00 73 00 65 00 72 00 6b 00 2e 00 65 00 78 00 65 00 } //1 \Microsoft\Windows\hdiserk.exe
		$a_01_3 = {5c 00 4d 00 69 00 63 00 72 00 6f 00 73 00 6f 00 66 00 74 00 5c 00 57 00 69 00 6e 00 64 00 6f 00 77 00 73 00 5c 00 70 00 61 00 67 00 65 00 69 00 6d 00 67 00 2e 00 74 00 6d 00 70 00 } //1 \Microsoft\Windows\pageimg.tmp
		$a_01_4 = {68 61 6c 69 6d 61 74 6f 75 64 69 } //1 halimatoudi
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=3
 
}