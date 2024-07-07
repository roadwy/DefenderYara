
rule TrojanDownloader_Win32_Chekafe_A{
	meta:
		description = "TrojanDownloader:Win32/Chekafe.A,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 06 00 00 "
		
	strings :
		$a_01_0 = {26 6c 6f 63 6b 63 6f 64 65 3d 25 64 26 6d 61 63 3d 25 73 00 } //1 氦捯捫摯㵥搥洦捡┽s
		$a_00_1 = {25 73 3f 69 64 3d 25 73 26 69 73 57 61 6e 67 42 61 72 3d 31 00 } //1
		$a_00_2 = {26 50 63 54 79 70 65 3d 57 61 6e 67 62 61 72 50 63 26 } //1 &PcType=WangbarPc&
		$a_01_3 = {b2 e5 c8 eb b9 e3 b8 e6 42 48 4f b2 e5 bc fe 2c } //1
		$a_01_4 = {ba d9 ba d9 2c d5 e2 ca c7 b1 ea cd b7 c5 b6 00 } //1
		$a_01_5 = {6b db 2b 69 c0 82 00 00 00 6b ff 33 03 c6 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=3
 
}