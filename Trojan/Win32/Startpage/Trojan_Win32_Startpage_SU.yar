
rule Trojan_Win32_Startpage_SU{
	meta:
		description = "Trojan:Win32/Startpage.SU,SIGNATURE_TYPE_PEHSTR_EXT,09 00 09 00 04 00 00 "
		
	strings :
		$a_01_0 = {33 00 36 00 30 00 53 00 61 00 66 00 65 00 74 00 72 00 61 00 79 00 } //2 360Safetray
		$a_01_1 = {41 00 64 00 6f 00 62 00 65 00 5c 00 73 00 6f 00 6d 00 65 00 74 00 68 00 69 00 6e 00 67 00 2e 00 69 00 6e 00 69 00 } //3 Adobe\something.ini
		$a_01_2 = {53 6f 67 6f 75 45 78 70 6c 6f 72 65 72 5c 43 6f 6e 66 69 67 2e 78 6d 6c } //2 SogouExplorer\Config.xml
		$a_01_3 = {48 69 6a 61 63 6b 49 45 } //2 HijackIE
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*3+(#a_01_2  & 1)*2+(#a_01_3  & 1)*2) >=9
 
}