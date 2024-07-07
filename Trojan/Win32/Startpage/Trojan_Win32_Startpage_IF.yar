
rule Trojan_Win32_Startpage_IF{
	meta:
		description = "Trojan:Win32/Startpage.IF,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {8b 44 24 0c 8d 0c 02 a1 90 01 04 8a 04 30 30 01 46 42 3b 54 24 10 7c e1 90 00 } //1
		$a_01_1 = {2a 49 6e 74 65 72 6e 65 74 2a 2e 6c 6e 6b 22 20 2f 73 } //1 *Internet*.lnk" /s
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}