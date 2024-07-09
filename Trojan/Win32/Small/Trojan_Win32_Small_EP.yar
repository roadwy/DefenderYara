
rule Trojan_Win32_Small_EP{
	meta:
		description = "Trojan:Win32/Small.EP,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_03_0 = {47 c6 44 24 ?? 61 c6 44 24 ?? 6d 88 5c 24 ?? c6 44 24 ?? 44 c6 44 24 ?? 6c c6 44 24 ?? 2e 88 5c 24 ?? c6 44 24 ?? 78 88 5c 24 } //2
		$a_01_1 = {5c 76 62 63 66 67 2e 69 6e 69 } //2 \vbcfg.ini
		$a_01_2 = {51 51 47 61 6d 65 44 6c 2e 65 78 65 } //1 QQGameDl.exe
		$a_01_3 = {53 6f 25 73 5c 25 73 5c 25 73 00 00 66 74 77 61 72 65 } //1
	condition:
		((#a_03_0  & 1)*2+(#a_01_1  & 1)*2+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}