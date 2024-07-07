
rule TrojanDownloader_Win32_Chronkeru_A{
	meta:
		description = "TrojanDownloader:Win32/Chronkeru.A,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 0e 00 00 "
		
	strings :
		$a_01_0 = {45 6d 67 6c 43 6c 5a 31 75 32 64 78 74 42 4d 41 38 43 45 38 44 59 58 30 65 4a 4f 6e 6d 52 4c 72 44 7a 75 54 49 36 6a 43 63 54 75 70 2b 53 6e 31 4f 6a 34 4e 77 52 62 33 78 61 34 55 69 73 62 77 78 61 6e 78 } //5 EmglClZ1u2dxtBMA8CE8DYX0eJOnmRLrDzuTI6jCcTup+Sn1Oj4NwRb3xa4Uisbwxanx
		$a_01_1 = {51 4b 36 67 58 76 57 38 45 37 31 2b 4b 6b 2b 63 43 39 38 45 2b 61 30 39 4a 6d 4c 63 4b 49 31 4f 64 74 39 66 47 78 6b 68 4c 6a 4e 72 6f 6c 6f 76 57 75 35 79 6d 30 56 75 4d 77 7a 31 4f 2f 57 30 4f } //4 QK6gXvW8E71+Kk+cC98E+a09JmLcKI1Odt9fGxkhLjNrolovWu5ym0VuMwz1O/W0O
		$a_01_2 = {4a 74 61 33 50 6d 6a 55 33 79 6e 42 50 6d 4b 6f 38 76 42 68 34 4c 62 55 71 2b 59 69 75 61 2f 66 51 6e 39 53 6c 4e 61 4d 30 34 43 6d 49 30 61 43 53 4c 7a 65 6b 71 7a 6f } //4 Jta3PmjU3ynBPmKo8vBh4LbUq+Yiua/fQn9SlNaM04CmI0aCSLzekqzo
		$a_01_3 = {51 4b 36 6c 39 74 53 70 53 6a 70 6d 70 56 67 61 63 4c 67 2b 2b 36 6d 30 64 6d 44 41 53 66 6a 6b 64 56 43 66 47 69 44 64 43 4d 78 48 7a 64 6a 43 44 76 77 68 4c 41 3d 3d } //4 QK6l9tSpSjpmpVgacLg++6m0dmDASfjkdVCfGiDdCMxHzdjCDvwhLA==
		$a_01_4 = {39 38 38 39 34 33 75 69 64 68 66 75 34 33 38 39 37 34 33 34 33 34 33 66 64 32 32 } //2 988943uidhfu43897434343fd22
		$a_01_5 = {47 4c 35 66 52 76 46 59 2b 7a 59 7a 6f 71 50 } //2 GL5fRvFY+zYzoqP
		$a_01_6 = {47 5a 36 33 59 74 39 64 4c 62 4c 51 6f 77 3d 3d } //2 GZ63Yt9dLbLQow==
		$a_01_7 = {56 39 72 75 32 41 77 2b 2b 5a 6e 4e 78 56 54 69 46 72 2b 6a 37 6b 4e 62 } //2 V9ru2Aw++ZnNxVTiFr+j7kNb
		$a_01_8 = {46 37 46 69 61 56 49 79 7a 33 38 36 7a 53 75 4e 4c 51 3d 3d } //2 F7FiaVIyz386zSuNLQ==
		$a_01_9 = {4a 74 77 6e 6f 36 50 46 6f 32 76 62 63 6f 69 37 7a 70 7a 71 4c 56 34 50 } //2 Jtwno6PFo2vbcoi7zpzqLV4P
		$a_01_10 = {64 64 6d 6d 79 79 79 79 } //1 ddmmyyyy
		$a_01_11 = {47 36 32 75 48 45 79 34 39 51 3d 3d } //1 G62uHEy49Q==
		$a_01_12 = {45 51 33 56 6b 55 71 6e 39 74 59 61 42 4f 35 6d } //1 EQ3VkUqn9tYaBO5m
		$a_01_13 = {4d 78 66 30 6d 47 46 41 46 4d 49 46 4a 67 62 78 71 37 49 3d } //1 Mxf0mGFAFMIFJgbxq7I=
	condition:
		((#a_01_0  & 1)*5+(#a_01_1  & 1)*4+(#a_01_2  & 1)*4+(#a_01_3  & 1)*4+(#a_01_4  & 1)*2+(#a_01_5  & 1)*2+(#a_01_6  & 1)*2+(#a_01_7  & 1)*2+(#a_01_8  & 1)*2+(#a_01_9  & 1)*2+(#a_01_10  & 1)*1+(#a_01_11  & 1)*1+(#a_01_12  & 1)*1+(#a_01_13  & 1)*1) >=8
 
}