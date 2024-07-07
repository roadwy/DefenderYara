
rule Trojan_Win32_TopAntiSpyware{
	meta:
		description = "Trojan:Win32/TopAntiSpyware,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_00_0 = {57 49 4e 44 4f 57 53 5c 57 65 62 5c 64 65 73 6b 74 6f 70 2e 68 74 6d 6c } //1 WINDOWS\Web\desktop.html
		$a_00_1 = {63 6f 6d 2e 6d 73 2e 61 70 70 6c 65 74 2e 65 6e 61 62 6c 65 2e } //1 com.ms.applet.enable.
		$a_00_2 = {00 63 3a 5c 72 2e 65 78 65 00 } //1
		$a_02_3 = {57 49 4e 44 4f 57 53 5c 53 79 73 74 65 6d 33 32 5c 90 02 05 73 72 76 33 32 2e 65 78 65 90 00 } //1
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_02_3  & 1)*1) >=4
 
}