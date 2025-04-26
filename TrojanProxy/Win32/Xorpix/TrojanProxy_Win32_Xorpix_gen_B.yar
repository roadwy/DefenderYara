
rule TrojanProxy_Win32_Xorpix_gen_B{
	meta:
		description = "TrojanProxy:Win32/Xorpix.gen!B,SIGNATURE_TYPE_PEHSTR_EXT,15 00 14 00 0b 00 00 "
		
	strings :
		$a_00_0 = {55 70 61 63 6b } //3 Upack
		$a_00_1 = {55 8b ec 81 c4 fc fe ff ff 57 56 53 } //2
		$a_00_2 = {85 c0 8b fe be ff ff ff ff 8d 3d } //2
		$a_00_3 = {8d bd fc fe ff ff b9 04 01 00 00 } //2
		$a_02_4 = {8b ec 81 c4 fc fe ff ff 8d 05 ?? 13 40 00 e8 ?? ?? 00 00 50 8d 85 fc fe ff ff 50 68 04 01 00 00 e8 ?? ?? 00 00 [0-03] e8 ?? ?? 00 00 59 33 c1 [0-03] 8b d0 ff 75 08 52 8d 15 ?? ?? 40 00 52 87 d2 8d 95 } //6
		$a_02_5 = {55 8b ec 56 57 53 8b 45 08 [0-02] 8b f8 [0-03] 8b 75 10 [0-02] 8b df [0-03] 87 d2 [0-02] 03 5d 0c [0-02] 8a 06 [0-05] 86 c0 30 27 [0-03] 83 c7 01 [0-03] 46 [0-03] 3b fb 74 } //6
		$a_00_6 = {47 65 74 54 69 63 6b 43 6f 75 6e 74 } //1 GetTickCount
		$a_00_7 = {47 65 74 54 65 6d 70 50 61 74 68 41 } //1 GetTempPathA
		$a_00_8 = {41 64 64 41 74 6f 6d 41 } //1 AddAtomA
		$a_00_9 = {46 69 6e 64 46 69 72 73 74 46 69 6c 65 41 } //1 FindFirstFileA
		$a_00_10 = {46 69 6e 64 52 65 73 6f 75 72 63 65 41 } //1 FindResourceA
	condition:
		((#a_00_0  & 1)*3+(#a_00_1  & 1)*2+(#a_00_2  & 1)*2+(#a_00_3  & 1)*2+(#a_02_4  & 1)*6+(#a_02_5  & 1)*6+(#a_00_6  & 1)*1+(#a_00_7  & 1)*1+(#a_00_8  & 1)*1+(#a_00_9  & 1)*1+(#a_00_10  & 1)*1) >=20
 
}