
rule Trojan_Win32_Emotet_DSS_MTB{
	meta:
		description = "Trojan:Win32/Emotet.DSS!MTB,SIGNATURE_TYPE_PEHSTR,01 00 01 00 05 00 00 "
		
	strings :
		$a_01_0 = {62 43 75 4e 55 6b 2a 64 7c 50 51 64 37 6c 23 7c 57 40 31 52 40 63 4b 7b 50 33 6a 40 47 6e 71 41 61 4c } //1 bCuNUk*d|PQd7l#|W@1R@cK{P3j@GnqAaL
		$a_01_1 = {6c 6a 3f 4b 33 5a 48 30 57 66 6d 25 61 73 4b 4a 54 33 6f 47 67 23 62 38 43 33 70 6f 70 63 61 35 61 58 6a 6a 41 34 4c } //1 lj?K3ZH0Wfm%asKJT3oGg#b8C3popca5aXjjA4L
		$a_01_2 = {57 49 47 52 64 35 66 61 71 6c 50 7c 65 37 7e 4d 5a 4c 57 42 25 36 50 46 6a 45 4a 58 24 49 49 } //1 WIGRd5faqlP|e7~MZLWB%6PFjEJX$II
		$a_01_3 = {3f 53 46 67 79 71 7e 51 7d 2a 58 40 70 75 78 53 6f 36 33 6d 4e 40 6a 52 68 33 43 4f 76 5a 64 79 5a 5a 4d 44 59 43 25 6b } //1 ?SFgyq~Q}*X@puxSo63mN@jRh3COvZdyZZMDYC%k
		$a_01_4 = {4c 62 78 76 72 4e 67 32 63 72 72 4b 62 6a 40 70 62 79 76 73 43 4b 6a 37 4b 75 51 70 4c } //1 LbxvrNg2crrKbj@pbyvsCKj7KuQpL
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=1
 
}