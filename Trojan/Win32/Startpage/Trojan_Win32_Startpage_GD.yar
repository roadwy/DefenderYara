
rule Trojan_Win32_Startpage_GD{
	meta:
		description = "Trojan:Win32/Startpage.GD,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_02_0 = {53 4f 46 54 57 41 52 45 5c 4d 69 63 72 6f 73 6f 66 74 5c 41 64 76 61 6e 63 65 64 20 49 4e 46 20 53 65 74 75 70 90 02 04 ff ff ff ff 07 00 00 00 73 74 72 4c 69 6e 6b 00 ff ff ff ff 14 00 00 00 68 74 74 70 3a 2f 2f 77 77 77 2e 31 31 38 38 2e 63 6f 6d 2f 90 00 } //1
		$a_00_1 = {53 65 74 4c 61 79 65 72 65 64 57 69 6e 64 6f 77 41 74 74 72 69 62 75 74 65 73 } //1 SetLayeredWindowAttributes
	condition:
		((#a_02_0  & 1)*1+(#a_00_1  & 1)*1) >=2
 
}