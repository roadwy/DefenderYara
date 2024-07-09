
rule Trojan_Win32_Startpage_GQ{
	meta:
		description = "Trojan:Win32/Startpage.GQ,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {66 78 36 37 38 54 6f 6f 6c 62 61 72 2e 64 6c 6c 00 } //1
		$a_01_1 = {49 6e 74 65 72 6e 65 74 20 45 78 70 6c 6f 72 65 72 2e 75 72 6c 00 } //1
		$a_03_2 = {b9 05 01 00 00 e8 ?? ?? ?? ?? 83 7d e4 00 74 1f 8b 45 e4 e8 ?? ?? ?? ?? 8b 55 e4 80 7c 02 ff 5c 74 0d } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_03_2  & 1)*1) >=3
 
}