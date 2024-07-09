
rule TrojanSpy_Win32_Banker_VBD{
	meta:
		description = "TrojanSpy:Win32/Banker.VBD,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 03 00 00 "
		
	strings :
		$a_00_0 = {40 67 6d 61 69 6c 2e 63 6f 6d } //1 @gmail.com
		$a_00_1 = {6d 73 6e 5f 6c 69 76 65 72 73 2e 65 78 65 } //1 msn_livers.exe
		$a_03_2 = {83 c4 f0 b8 ?? ?? 48 00 e8 ?? ?? ?? ff a1 ?? ?? 48 00 8b 00 e8 ?? ?? ?? ff 68 ?? ?? 48 00 6a 00 e8 ?? ?? ?? ff 85 c0 75 58 a1 ?? ?? 48 00 8b 00 ba ?? ?? 48 00 e8 ?? ?? ?? ff 8b 0d ?? ?? 48 00 a1 ?? ?? 48 00 8b 00 8b 15 ?? ?? 47 00 } //2
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_03_2  & 1)*2) >=4
 
}