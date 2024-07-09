
rule Backdoor_Win32_CobaltStrikeLoader_HC_dha{
	meta:
		description = "Backdoor:Win32/CobaltStrikeLoader.HC!dha,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {8b 54 24 0c 8b c2 e8 ?? ?? ?? ?? ?? ?? e3 b6 00 74 03 } //1
		$a_01_1 = {21 54 68 69 73 20 69 73 20 61 20 57 69 6e 64 6f 77 73 20 4e 54 20 77 69 6e 64 6f 77 65 64 20 64 79 6e 61 6d 69 63 20 6c 69 6e 6b 20 6c 69 62 72 61 72 79 } //1 !This is a Windows NT windowed dynamic link library
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}