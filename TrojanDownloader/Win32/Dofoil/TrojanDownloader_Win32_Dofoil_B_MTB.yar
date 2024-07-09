
rule TrojanDownloader_Win32_Dofoil_B_MTB{
	meta:
		description = "TrojanDownloader:Win32/Dofoil.B!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 05 00 00 "
		
	strings :
		$a_03_0 = {0f b6 40 02 eb ?? ?? 40 eb ?? ?? ?? ?? ?? b9 ?? ?? ?? ?? eb ?? ?? ?? ?? ?? eb ?? ?? eb ?? ?? f7 e1 eb ?? ?? ?? ?? ?? ?? 01 d8 74 07 75 05 ?? ?? ?? ?? ?? 50 c3 } //2
		$a_03_1 = {8b 4c 24 04 57 f7 c1 03 00 00 00 74 ?? 8a 01 41 84 c0 74 ?? f7 c1 03 00 00 00 75 ?? 8b 01 ba ff fe fe 7e 03 d0 83 f0 ff 33 c2 83 c1 04 a9 00 01 01 81 } //2
		$a_00_2 = {5c 64 72 69 76 65 72 73 5c 74 63 70 69 70 2e 73 79 73 } //1 \drivers\tcpip.sys
		$a_00_3 = {64 72 69 76 65 72 73 5c 62 65 65 70 2e 73 79 73 } //1 drivers\beep.sys
		$a_00_4 = {64 75 6d 70 5f 64 75 6d 70 66 76 65 2e 73 79 73 } //1 dump_dumpfve.sys
	condition:
		((#a_03_0  & 1)*2+(#a_03_1  & 1)*2+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1) >=7
 
}