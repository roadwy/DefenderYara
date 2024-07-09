
rule Trojan_Win32_Startpage_JW{
	meta:
		description = "Trojan:Win32/Startpage.JW,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_00_0 = {50 6f 70 41 64 4d 75 74 65 78 } //1 PopAdMutex
		$a_03_1 = {68 74 74 70 3a 2f 2f 39 31 ?? ?? 2e 69 6e 66 6f 3a 31 31 38 38 2f ?? 2e 68 74 6d 6c } //1
		$a_00_2 = {41 6e 74 69 2d 4b 41 56 2e 65 78 65 } //1 Anti-KAV.exe
		$a_00_3 = {49 6e 74 65 72 6e 6f 74 20 45 78 70 6c 6f 72 65 72 2e 75 72 6c } //1 Internot Explorer.url
	condition:
		((#a_00_0  & 1)*1+(#a_03_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1) >=4
 
}