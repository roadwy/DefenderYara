
rule Backdoor_BAT_Remcos_VPA_MTB{
	meta:
		description = "Backdoor:BAT/Remcos.VPA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,13 00 13 00 13 00 00 "
		
	strings :
		$a_81_0 = {24 33 34 36 64 62 61 39 30 2d 35 32 65 62 2d 34 65 34 66 2d 61 38 39 39 2d 30 37 37 37 38 63 31 34 66 38 66 32 } //1 $346dba90-52eb-4e4f-a899-07778c14f8f2
		$a_81_1 = {6e 56 69 72 74 4b 65 79 } //1 nVirtKey
		$a_01_2 = {43 00 3a 00 5c 00 55 00 73 00 65 00 72 00 73 00 5c 00 43 00 65 00 63 00 65 00 69 00 6c 00 69 00 61 00 5c 00 44 00 6f 00 63 00 75 00 6d 00 65 00 6e 00 74 00 73 00 } //1 C:\Users\Ceceilia\Documents
		$a_81_3 = {59 46 53 57 49 62 69 38 53 6a 79 78 2b 30 56 6c 41 30 75 55 77 76 50 54 73 63 36 7a 30 77 6c 36 7a 65 31 78 4c 6d 7a 67 43 64 4e 58 5a 42 52 43 44 6c 55 70 4c 44 77 43 63 49 51 6e 74 59 78 52 71 4e 39 35 39 35 2b 59 5a 64 74 6a 36 38 5a 58 30 4f } //1 YFSWIbi8Sjyx+0VlA0uUwvPTsc6z0wl6ze1xLmzgCdNXZBRCDlUpLDwCcIQntYxRqN9595+YZdtj68ZX0O
		$a_81_4 = {66 46 59 55 35 48 46 73 35 4d 51 35 55 32 5a 50 6d 6a 42 33 59 6c 58 64 6c 41 6d 54 71 79 5a 4d 6e 6a 69 33 61 6b 72 74 33 4a 71 71 4f 52 4e 50 71 52 30 66 48 52 2b 64 50 57 55 79 30 49 4f 67 71 4c 61 32 75 6f 62 2b 59 54 4a 66 57 73 } //1 fFYU5HFs5MQ5U2ZPmjB3YlXdlAmTqyZMnji3akrt3JqqORNPqR0fHR+dPWUy0IOgqLa2uob+YTJfWs
		$a_81_5 = {32 6f 38 49 50 65 72 76 42 34 35 2b 43 68 59 4e 37 43 46 67 53 4d 39 70 62 31 38 59 53 79 52 46 57 42 65 50 38 30 69 50 6e 69 4f 6a 6d 44 33 7a 78 49 76 38 6e 33 67 55 } //1 2o8IPervB45+ChYN7CFgSM9pb18YSyRFWBeP80iPniOjmD3zxIv8n3gU
		$a_81_6 = {72 6c 4d 73 66 67 4c 67 71 50 67 38 6a 4f 58 34 2b 44 30 30 4e 38 4f 4e 4b 36 46 6a 41 66 38 30 55 43 46 52 73 6e 6d 43 72 61 55 4e 61 4f 75 5a 30 76 77 31 73 41 57 73 54 50 52 62 30 41 39 56 } //1 rlMsfgLgqPg8jOX4+D00N8ONK6FjAf80UCFRsnmCraUNaOuZ0vw1sAWsTPRb0A9V
		$a_81_7 = {34 55 38 33 6e 39 34 38 4e 69 6e 59 45 } //1 4U83n948NinYE
		$a_81_8 = {63 51 61 46 37 73 66 38 57 51 54 } //1 cQaF7sf8WQT
		$a_81_9 = {42 71 6f 69 41 73 45 36 43 74 54 4f 45 48 69 7a 4a 7a 75 58 66 63 39 4f 76 36 32 6a 57 4d 6f 7a 47 41 4d 31 67 50 4d 61 79 77 45 75 68 4a 35 37 64 } //1 BqoiAsE6CtTOEHizJzuXfc9Ov62jWMozGAM1gPMaywEuhJ57d
		$a_81_10 = {4d 63 43 43 6d 6a 4b 41 69 73 42 2b 50 6f 54 72 4c 53 53 34 39 54 30 } //1 McCCmjKAisB+PoTrLSS49T0
		$a_81_11 = {5a 76 41 31 76 48 4d 61 53 69 58 78 32 7a 67 64 4f 42 66 48 50 68 5a 6c 70 45 72 44 78 38 77 31 73 6e 33 37 77 61 33 4d 59 36 58 66 30 35 44 54 71 50 30 37 54 63 48 4a 59 4e 4d 6a 4f 6a 6f 50 49 72 4f 59 66 70 45 66 5a 71 2b 51 4a 2b 75 7a 39 53 6a 2b 69 79 39 52 71 64 50 59 62 77 44 35 71 35 41 53 57 4e 32 } //1 ZvA1vHMaSiXx2zgdOBfHPhZlpErDx8w1sn37wa3MY6Xf05DTqP07TcHJYNMjOjoPIrOYfpEfZq+QJ+uz9Sj+iy9RqdPYbwD5q5ASWN2
		$a_81_12 = {4b 73 47 6c 66 6c 43 7a 79 54 49 56 4f 46 38 5a 54 6c 2b 45 76 53 30 44 36 42 71 49 62 4b 61 4a 61 42 35 4f 65 52 52 7a 56 6f 78 31 69 37 31 47 73 61 38 42 63 42 5a 7a 32 63 51 56 35 32 55 39 57 4b } //1 KsGlflCzyTIVOF8ZTl+EvS0D6BqIbKaJaB5OeRRzVox1i71Gsa8BcBZz2cQV52U9WK
		$a_81_13 = {39 61 79 4e 30 64 2b 76 48 41 2b 7a 32 53 34 55 47 35 54 57 38 45 4a } //1 9ayN0d+vHA+z2S4UG5TW8EJ
		$a_81_14 = {48 71 41 63 74 59 37 51 54 43 76 36 48 56 79 48 35 } //1 HqActY7QTCv6HVyH5
		$a_81_15 = {56 4a 6a 37 37 38 49 46 6f 58 79 66 55 53 6b 74 59 38 76 38 6c } //1 VJj778IFoXyfUSktY8v8l
		$a_81_16 = {53 76 4d 45 4c 74 76 46 6d 4a 38 43 74 41 74 79 7a 52 34 6c } //1 SvMELtvFmJ8CtAtyzR4l
		$a_81_17 = {78 50 4a 64 42 4b 58 36 64 46 7a 6a 70 58 73 69 65 51 36 6c 63 2b 72 41 31 61 47 38 37 49 4f 4e 48 53 44 38 33 39 6c 37 76 2b 61 5a 36 62 49 31 6d 74 6d } //1 xPJdBKX6dFzjpXsieQ6lc+rA1aG87IONHSD839l7v+aZ6bI1mtm
		$a_81_18 = {44 55 2b 5a 46 48 41 41 4f 41 41 41 } //1 DU+ZFHAAOAAA
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_01_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1+(#a_81_5  & 1)*1+(#a_81_6  & 1)*1+(#a_81_7  & 1)*1+(#a_81_8  & 1)*1+(#a_81_9  & 1)*1+(#a_81_10  & 1)*1+(#a_81_11  & 1)*1+(#a_81_12  & 1)*1+(#a_81_13  & 1)*1+(#a_81_14  & 1)*1+(#a_81_15  & 1)*1+(#a_81_16  & 1)*1+(#a_81_17  & 1)*1+(#a_81_18  & 1)*1) >=19
 
}