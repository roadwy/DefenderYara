
rule Backdoor_Win32_Farfli_H{
	meta:
		description = "Backdoor:Win32/Farfli.H,SIGNATURE_TYPE_PEHSTR_EXT,47 00 47 00 04 00 00 "
		
	strings :
		$a_02_0 = {43 6f 70 79 46 69 6c 65 41 [0-04] 57 69 6e 45 78 65 63 [0-04] 4f 70 65 6e 50 72 6f 63 65 73 73 } //1
		$a_02_1 = {8d 85 fc fe ff ff 68 ?? ?? 40 00 50 e8 ?? ?? 00 00 59 59 83 7d 0c 00 56 be ?? ?? 40 00 75 05 be ?? ?? 40 00 83 7d 0c 00 b8 ?? ?? 40 00 75 05 b8 ?? ?? 40 00 50 b8 ?? ?? 40 00 68 ?? ?? 40 00 50 50 8d 85 fc fe ff ff 50 68 ?? ?? 40 00 56 ff 15 ?? ?? 40 00 83 c4 1c 8b c6 5e c9 c3 } //40
		$a_00_2 = {7d 00 00 5c 00 00 00 53 6f 66 74 77 61 72 65 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 65 78 70 6c 6f 72 45 52 5c 53 68 65 6c 6c 45 78 65 63 75 74 65 48 6f 6f 6b 73 00 00 00 00 54 68 72 65 61 64 69 6e 67 4d 6f 64 65 6c 00 00 41 70 61 72 74 6d 65 6e 74 00 } //10
		$a_00_3 = {40 65 63 68 6f 20 6f 66 66 0d 0a 3a 4c 6f 6f 70 0d 0a 61 74 74 72 69 62 20 22 25 73 22 20 2d 72 20 2d 61 20 2d 73 20 2d 68 0d 0a 64 65 6c 20 22 25 73 22 0d 0a 69 66 20 65 78 69 73 74 20 22 25 73 22 20 67 6f 74 6f 20 4c 6f 6f 70 0d 0a 64 65 6c 20 25 25 30 0d 0a } //20
	condition:
		((#a_02_0  & 1)*1+(#a_02_1  & 1)*40+(#a_00_2  & 1)*10+(#a_00_3  & 1)*20) >=71
 
}