
rule Trojan_Win32_Redline_GEF_MTB{
	meta:
		description = "Trojan:Win32/Redline.GEF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0b 00 0b 00 02 00 00 "
		
	strings :
		$a_03_0 = {8a 3c 3e 8b c6 83 e0 03 ba ?? ?? ?? ?? 8a 98 ?? ?? ?? ?? 32 df e8 ?? ?? ?? ?? 8b f8 8b 0f 8b 49 ?? 8b 4c 39 ?? 8b 49 ?? 89 4c 24 } //10
		$a_03_1 = {5c 00 4d 00 69 00 63 00 72 00 6f 00 73 00 6f 00 66 00 74 00 2e 00 4e 00 45 00 54 00 5c 00 46 00 72 00 61 00 6d 00 65 00 77 00 6f 00 72 00 6b 00 5c 00 [0-20] 5c 00 76 00 62 00 63 00 2e 00 65 00 78 00 65 00 } //1
	condition:
		((#a_03_0  & 1)*10+(#a_03_1  & 1)*1) >=11
 
}