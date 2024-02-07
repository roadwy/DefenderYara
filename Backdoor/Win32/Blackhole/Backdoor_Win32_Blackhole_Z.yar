
rule Backdoor_Win32_Blackhole_Z{
	meta:
		description = "Backdoor:Win32/Blackhole.Z,SIGNATURE_TYPE_PEHSTR_EXT,17 00 17 00 08 00 00 01 00 "
		
	strings :
		$a_00_0 = {73 74 72 53 65 72 76 65 72 43 6c 61 73 73 4e 61 6d 65 } //01 00  strServerClassName
		$a_00_1 = {3d 6d 4c 47 2b 41 4d 32 57 51 7a 63 69 52 38 77 } //01 00  =mLG+AM2WQzciR8w
		$a_00_2 = {3a 28 52 61 6d 20 44 69 73 6b 29 } //01 00  :(Ram Disk)
		$a_00_3 = {53 65 74 20 63 64 61 75 64 69 6f 20 64 6f 6f 72 20 6f 70 65 6e } //01 00  Set cdaudio door open
		$a_00_4 = {62 72 63 5f 53 65 72 76 65 72 2e 65 78 65 } //01 00  brc_Server.exe
		$a_00_5 = {63 3a 5c 62 72 63 6c 6f 67 2e 74 78 74 } //0a 00  c:\brclog.txt
		$a_02_6 = {0f 84 8e 00 00 00 b8 90 01 04 ba 1c 00 00 00 e8 90 01 04 c7 05 90 01 04 10 01 00 00 c7 05 90 01 04 02 00 00 00 c7 05 90 01 04 03 00 00 00 c7 05 90 01 04 e8 03 00 00 68 90 01 04 a1 90 01 04 50 e8 90 01 04 c6 05 90 01 04 00 c6 05 90 01 04 00 c7 05 90 01 04 04 00 00 00 90 00 } //0a 00 
		$a_02_7 = {54 52 65 67 4d 6f 6e 69 74 6f 72 54 68 72 65 61 64 55 8b ec 53 56 57 84 d2 74 08 83 c4 f0 e8 90 01 04 8b f1 8b da 8b f8 b1 01 33 d2 8b c7 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}