
rule Trojan_Win32_Startpage_XK_dll{
	meta:
		description = "Trojan:Win32/Startpage.XK!dll,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {2e 36 64 75 64 75 2e 63 6f 6d } //1 .6dudu.com
		$a_01_1 = {2f 2f 31 32 32 2e 32 32 34 2e 39 2e 31 31 33 3a 38 30 32 32 2f 49 6e 73 65 72 74 62 7a 2e 61 73 70 78 3f } //1 //122.224.9.113:8022/Insertbz.aspx?
		$a_03_2 = {5c 73 6f 66 74 70 72 6f 2e 64 6c 6c ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 62 6f 6f 74 69 6e 73 74 61 6c 6c 2e 67 69 66 ?? ?? ?? ?? ?? ?? ?? ?? ?? 5c 6a 65 63 74 2e 76 62 73 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_03_2  & 1)*1) >=3
 
}