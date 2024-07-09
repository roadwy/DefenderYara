
rule Trojan_Win32_FileCoder_XY_MTB{
	meta:
		description = "Trojan:Win32/FileCoder.XY!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {8b 44 24 6c 8b 4c 24 60 89 38 5f 89 48 04 8b 8c 24 ?? ?? ?? ?? 5e 5b 33 cc e8 ?? ?? ?? ?? 8b e5 5d c3 } //1
		$a_00_1 = {33 f3 2b fe 8b 44 24 74 29 44 24 10 83 6c 24 64 01 0f 85 67 fb ff ff } //1
	condition:
		((#a_03_0  & 1)*1+(#a_00_1  & 1)*1) >=2
 
}