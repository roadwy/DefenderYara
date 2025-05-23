
rule Backdoor_Win32_Likseput_B{
	meta:
		description = "Backdoor:Win32/Likseput.B,SIGNATURE_TYPE_PEHSTR_EXT,06 00 05 00 0c 00 00 "
		
	strings :
		$a_01_0 = {d0 f8 24 7f 42 3b d7 88 01 72 e7 } //2
		$a_01_1 = {d0 e9 88 4c 05 88 40 83 f8 32 7c f0 } //2
		$a_03_2 = {6a 23 50 ff d6 8b d8 59 85 db 59 0f 84 ?? ?? 00 00 6a 2e 53 ff d6 59 85 c0 59 0f 84 ?? ?? 00 00 80 20 00 } //2
		$a_01_3 = {3c 23 75 05 c6 01 3a eb 1d 33 d2 38 44 15 bc 74 06 } //2
		$a_01_4 = {39 6e 24 74 0c bb 00 31 80 84 b8 bb 01 00 00 eb 08 6a 50 bb 00 01 00 84 58 } //2
		$a_01_5 = {25 64 2e 25 64 20 25 30 32 64 3a 25 30 32 64 20 25 73 5c 25 73 } //1 %d.%d %02d:%02d %s\%s
		$a_01_6 = {6c 69 73 74 20 3c 2f 70 7c 2f 73 7c 2f 64 3e } //1 list </p|/s|/d>
		$a_01_7 = {6b 69 6c 6c 20 3c 2f 70 7c 2f 73 3e 20 3c 70 69 64 7c 53 65 72 76 69 63 65 4e 61 6d 65 3e } //1 kill </p|/s> <pid|ServiceName>
		$a_01_8 = {73 74 61 72 74 20 3c 2f 70 7c 2f 73 3e 20 3c 66 69 6c 65 6e 61 6d 65 7c 53 65 72 76 69 63 65 4e 61 6d 65 3e } //1 start </p|/s> <filename|ServiceName>
		$a_01_9 = {67 65 74 66 2f 70 75 74 66 20 46 69 6c 65 4e 61 6d 65 20 3c 4e 3e } //1 getf/putf FileName <N>
		$a_01_10 = {53 68 65 6c 6c 20 73 74 61 72 74 65 64 20 73 75 63 63 65 73 73 66 75 6c 6c 79 21 } //1 Shell started successfully!
		$a_01_11 = {56 6f 6c 75 6d 65 20 6f 6e 20 74 68 69 73 20 63 6f 6d 70 75 74 65 72 3a } //1 Volume on this computer:
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2+(#a_03_2  & 1)*2+(#a_01_3  & 1)*2+(#a_01_4  & 1)*2+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1+(#a_01_8  & 1)*1+(#a_01_9  & 1)*1+(#a_01_10  & 1)*1+(#a_01_11  & 1)*1) >=5
 
}