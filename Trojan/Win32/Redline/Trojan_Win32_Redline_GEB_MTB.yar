
rule Trojan_Win32_Redline_GEB_MTB{
	meta:
		description = "Trojan:Win32/Redline.GEB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0b 00 0b 00 02 00 00 "
		
	strings :
		$a_03_0 = {83 e0 03 8a 98 ?? ?? ?? ?? 32 1c 2e e8 ?? ?? ?? ?? 8b f8 8b 0f 8b 49 ?? 8b 4c 39 ?? 8b 49 ?? 89 4c 24 ?? 8b 11 ff 52 } //10
		$a_03_1 = {5c 00 4d 00 69 00 63 00 72 00 6f 00 73 00 6f 00 66 00 74 00 2e 00 4e 00 45 00 54 00 5c 00 46 00 72 00 61 00 6d 00 65 00 77 00 6f 00 72 00 6b 00 5c 00 [0-20] 5c 00 76 00 62 00 63 00 2e 00 65 00 78 00 65 00 } //1
	condition:
		((#a_03_0  & 1)*10+(#a_03_1  & 1)*1) >=11
 
}