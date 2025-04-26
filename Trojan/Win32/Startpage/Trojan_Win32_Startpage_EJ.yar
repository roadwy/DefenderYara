
rule Trojan_Win32_Startpage_EJ{
	meta:
		description = "Trojan:Win32/Startpage.EJ,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_00_0 = {68 74 74 70 3a 2f 2f 74 6a 2e 6b 65 79 35 31 38 38 2e 63 6f 6d } //1 http://tj.key5188.com
		$a_03_1 = {33 c0 55 68 ?? ?? 40 00 64 ff 30 64 89 20 b8 ?? ?? 40 00 ba ?? ?? 40 00 e8 ?? ?? ff ff 6a 00 68 ?? ?? 40 00 a1 ?? ?? 40 00 e8 ?? ?? ff ff 50 68 ?? ?? 40 00 68 ?? ?? 40 00 6a 00 e8 ?? ?? ff ff 33 c0 5a 59 59 64 89 10 68 ?? ?? 40 00 } //1
	condition:
		((#a_00_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}