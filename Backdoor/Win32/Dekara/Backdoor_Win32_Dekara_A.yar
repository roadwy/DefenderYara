
rule Backdoor_Win32_Dekara_A{
	meta:
		description = "Backdoor:Win32/Dekara.A,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 08 00 0c 00 00 "
		
	strings :
		$a_01_0 = {54 10 40 00 09 75 54 43 50 46 6c 6f 6f 64 8b c0 } //3
		$a_01_1 = {72 65 76 72 65 53 5f 00 } //1 敲牶卥_
		$a_01_2 = {3d 64 69 77 68 3f 70 68 70 2e 74 63 65 6e 6e 6f 63 00 } //1
		$a_01_3 = {5d 70 6f 74 73 5f 70 74 74 68 5b 00 } //1 灝瑯彳瑰桴[
		$a_01_4 = {5d 74 72 61 74 73 65 72 5b 00 } //1 瑝慲獴牥[
		$a_01_5 = {5d 65 74 61 64 70 75 5b 00 } //1
		$a_01_6 = {5d 6c 6c 61 74 73 6e 69 6e 75 5b 00 } //1 汝慬獴楮畮[
		$a_01_7 = {5d 78 65 6c 64 5b 00 } //1
		$a_01_8 = {5d 74 69 73 69 76 5b 00 } //1 瑝獩癩[
		$a_01_9 = {46 32 46 32 41 33 30 37 34 37 34 37 38 36 00 } //1
		$a_01_10 = {67 72 61 62 62 65 72 2d 63 6f 6e 6e 65 63 74 2e 70 68 70 00 } //1
		$a_01_11 = {2e 68 61 72 64 63 6f 72 65 70 6f 72 6e 2e 63 6f 6d 2f 00 } //1
	condition:
		((#a_01_0  & 1)*3+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1+(#a_01_8  & 1)*1+(#a_01_9  & 1)*1+(#a_01_10  & 1)*1+(#a_01_11  & 1)*1) >=8
 
}