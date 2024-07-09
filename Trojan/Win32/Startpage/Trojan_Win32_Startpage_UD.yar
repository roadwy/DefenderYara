
rule Trojan_Win32_Startpage_UD{
	meta:
		description = "Trojan:Win32/Startpage.UD,SIGNATURE_TYPE_PEHSTR_EXT,0c 00 0c 00 04 00 00 "
		
	strings :
		$a_01_0 = {51 75 69 63 6b 20 4c 61 75 6e 63 68 00 00 20 68 74 74 70 3a 2f 2f 77 77 77 2e 31 31 34 2e 63 6f 6d 2e 63 6e 2f } //5
		$a_01_1 = {4d 6f 7a 69 6c 6c 61 20 46 69 72 65 66 6f 78 2e 6c 6e 6b } //1 Mozilla Firefox.lnk
		$a_01_2 = {49 6e 74 65 72 6e 65 74 20 45 78 70 6c 6f 72 65 72 2e 6c 6e 6b } //1 Internet Explorer.lnk
		$a_03_3 = {eb 7a 8b 44 24 (1c|2c) 51 50 8b 10 ff 52 50 8b 44 24 (1c|2c) 68 ?? ?? ?? 00 50 8b 08 ff 51 2c } //5
	condition:
		((#a_01_0  & 1)*5+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_03_3  & 1)*5) >=12
 
}