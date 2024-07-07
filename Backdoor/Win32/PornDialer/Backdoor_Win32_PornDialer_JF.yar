
rule Backdoor_Win32_PornDialer_JF{
	meta:
		description = "Backdoor:Win32/PornDialer.JF,SIGNATURE_TYPE_PEHSTR_EXT,15 00 15 00 05 00 00 "
		
	strings :
		$a_00_0 = {55 73 65 72 2d 41 67 65 6e 74 3a 20 49 54 44 69 61 6c 65 72 } //1 User-Agent: ITDialer
		$a_00_1 = {75 73 65 72 6e 61 6d 65 3d 25 73 26 6e 75 6d 62 65 72 3d 25 73 26 64 69 61 6c 65 72 69 64 3d 25 73 26 6d 61 78 74 69 6d 65 3d 25 64 } //1 username=%s&number=%s&dialerid=%s&maxtime=%d
		$a_00_2 = {77 00 77 00 77 00 2e 00 73 00 65 00 78 00 65 00 6c 00 6c 00 79 00 2e 00 63 00 6f 00 6d 00 } //1 www.sexelly.com
		$a_02_3 = {8b 8d 28 fe ff ff 6b c9 68 83 b9 90 01 04 00 75 16 68 90 01 04 8d 95 54 fc ff ff 52 e8 90 01 04 83 c4 08 eb 2a 8b 85 28 fe ff ff 6b c0 68 83 b8 90 01 04 01 75 16 68 90 01 04 8d 8d 54 fc ff ff 51 e8 90 01 04 83 c4 08 eb 02 eb 8d 68 c8 00 00 00 90 00 } //10
		$a_02_4 = {83 c4 08 85 c0 74 44 8d 95 30 f7 ff ff 52 8d 85 28 f5 ff ff 50 68 90 01 04 68 08 02 00 00 8d 8d 28 f5 ff ff 51 e8 90 01 04 83 c4 14 6a 00 8d 95 30 f7 ff ff 52 8d 85 28 f5 ff ff 50 68 90 01 04 e8 90 01 04 83 c4 10 6a 10 68 90 01 04 68 90 01 04 e8 90 01 04 83 c4 0c b9 90 01 04 e8 90 01 04 6a 00 8b 0d 90 01 04 51 ff 15 90 01 04 6a 00 6a 00 6a 12 8b 15 90 01 04 52 ff 15 90 01 04 e9 ba 00 00 00 81 7d 10 eb 03 00 00 90 00 } //10
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_02_3  & 1)*10+(#a_02_4  & 1)*10) >=21
 
}