
rule Backdoor_Win32_CobaltStrikeLoader_HCA_dha{
	meta:
		description = "Backdoor:Win32/CobaltStrikeLoader.HCA!dha,SIGNATURE_TYPE_PEHSTR_EXT,0b 00 0b 00 03 00 00 "
		
	strings :
		$a_03_0 = {8b 54 24 0c [0-02] e8 ?? ?? ?? ?? ?? ?? e3 b6 00 74 03 } //10
		$a_03_1 = {8b 54 24 0c [0-02] e8 ?? ?? ?? ?? ?? ef 49 12 00 74 03 } //10
		$a_01_2 = {21 54 68 69 73 20 69 73 20 61 20 57 69 6e 64 6f 77 73 20 4e 54 20 77 69 6e 64 6f 77 65 64 20 64 79 6e 61 6d 69 63 20 6c 69 6e 6b 20 6c 69 62 72 61 72 79 } //1 !This is a Windows NT windowed dynamic link library
	condition:
		((#a_03_0  & 1)*10+(#a_03_1  & 1)*10+(#a_01_2  & 1)*1) >=11
 
}