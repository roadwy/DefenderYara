
rule TrojanDownloader_Win32_Dogrobot_A{
	meta:
		description = "TrojanDownloader:Win32/Dogrobot.A,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 0b 00 00 "
		
	strings :
		$a_01_0 = {81 3d b0 d4 40 00 ae 08 00 00 0f 84 87 00 00 00 80 a5 f8 fe ff ff 00 6a 18 59 33 c0 } //4
		$a_01_1 = {8a 0c 32 8a c2 2c 3b 8b fe d0 e0 02 c8 33 c0 88 0c 32 83 c9 ff 42 f2 ae f7 d1 49 3b d1 72 e1 } //4
		$a_03_2 = {6a 01 68 99 03 00 00 90 17 07 01 01 01 01 01 01 04 50 51 52 53 56 57 68 ?? ?? ?? ?? 6a 01 e8 ?? ?? 00 00 83 c4 ?? 68 f4 01 00 00 ff 15 ?? ?? ?? ?? [0-10] 6a 05 } //4
		$a_00_3 = {5c 64 6f 77 6e 2e 73 79 73 } //1 \down.sys
		$a_00_4 = {25 30 32 58 2d 25 30 32 58 2d 25 30 32 58 2d 25 30 32 58 2d 25 30 32 58 2d 25 30 32 58 } //1 %02X-%02X-%02X-%02X-%02X-%02X
		$a_00_5 = {5c 64 72 69 76 65 72 73 5c 65 74 63 5c 68 6f 73 74 73 } //1 \drivers\etc\hosts
		$a_00_6 = {49 45 50 72 6f 74 41 63 63 65 73 73 } //1 IEProtAccess
		$a_00_7 = {3f 78 3d 00 26 79 3d 00 47 4f 4f 47 4c 45 } //1 砿=礦=佇䝏䕌
		$a_02_8 = {4d 79 45 6e 74 72 79 50 6f 69 6e 74 [0-05] 6c 70 6b 2e 64 6c 6c } //1
		$a_00_9 = {25 73 25 64 5f 72 65 73 2e 74 6d 70 } //1 %s%d_res.tmp
		$a_01_10 = {6b 61 6b 61 } //1 kaka
	condition:
		((#a_01_0  & 1)*4+(#a_01_1  & 1)*4+(#a_03_2  & 1)*4+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1+(#a_00_5  & 1)*1+(#a_00_6  & 1)*1+(#a_00_7  & 1)*1+(#a_02_8  & 1)*1+(#a_00_9  & 1)*1+(#a_01_10  & 1)*1) >=8
 
}