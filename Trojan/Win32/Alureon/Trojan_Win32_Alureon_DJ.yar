
rule Trojan_Win32_Alureon_DJ{
	meta:
		description = "Trojan:Win32/Alureon.DJ,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_03_0 = {6a 2f 57 ff 15 ?? ?? ?? ?? 85 c0 75 14 56 ff 15 ?? ?? ?? ?? 8d 44 30 ff 8b f0 2b f7 83 c6 01 eb 04 8b f0 2b f7 85 c0 74 ?? 6a 40 68 00 30 00 00 8d 46 01 50 6a 00 ff 15 } //2
		$a_01_1 = {53 6f 66 74 77 61 72 65 5c 68 38 73 72 74 } //2 Software\h8srt
		$a_00_2 = {3e 43 6c 69 63 6b 4d 65 3c 2f 61 3e 3c 73 63 72 69 70 74 20 74 79 70 65 3d 22 74 65 78 74 2f 6a 61 76 61 73 63 72 69 70 74 22 3e 72 65 64 69 72 65 63 74 2e 63 6c 69 63 6b 28 29 3b 3c 2f 73 63 72 69 70 74 3e } //1 >ClickMe</a><script type="text/javascript">redirect.click();</script>
		$a_01_3 = {73 6f 72 64 65 72 2e 64 6c 6c 00 00 57 53 50 53 74 61 72 74 75 70 00 } //1
	condition:
		((#a_03_0  & 1)*2+(#a_01_1  & 1)*2+(#a_00_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}