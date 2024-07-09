
rule Backdoor_Win32_PcClient_BE{
	meta:
		description = "Backdoor:Win32/PcClient.BE,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_00_0 = {50 63 43 6c 69 65 6e 74 2e 64 6c 6c 00 50 63 53 68 61 72 65 50 6c 61 79 57 6f 72 6b 00 } //1
		$a_03_1 = {51 8d 4e 0c 51 0f b7 0e 51 8d 4e ?? 51 ff b6 ?? ?? 00 00 ff b6 ?? ?? 00 00 ff d0 83 c4 18 68 b8 0b 00 00 ff b6 58 03 00 00 ff 15 ?? ?? ?? ?? 3d 02 01 00 00 } //1
	condition:
		((#a_00_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}