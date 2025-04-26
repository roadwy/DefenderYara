
rule Trojan_Win32_Zbot_HBAI_MTB{
	meta:
		description = "Trojan:Win32/Zbot.HBAI!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0e 00 0e 00 05 00 00 "
		
	strings :
		$a_02_0 = {8b 45 f4 33 45 f0 33 f0 3b f7 74 08 85 1d ?? ?? ?? ?? 75 05 be 4f e6 40 bb 89 35 ?? ?? ?? ?? f7 d6 89 35 ?? ?? ?? ?? 5e 5f 5b c9 c3 } //10
		$a_80_1 = {62 6b 78 74 6e 64 73 2e 65 78 65 } //bkxtnds.exe  1
		$a_80_2 = {62 6b 67 72 6e 64 2e 65 78 65 } //bkgrnd.exe  1
		$a_80_3 = {5a 75 68 61 6d 6f 68 69 6d 6f } //Zuhamohimo  1
		$a_80_4 = {48 75 77 65 6e 6f 6e 64 } //Huwenond  1
	condition:
		((#a_02_0  & 1)*10+(#a_80_1  & 1)*1+(#a_80_2  & 1)*1+(#a_80_3  & 1)*1+(#a_80_4  & 1)*1) >=14
 
}