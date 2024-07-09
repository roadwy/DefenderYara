
rule Backdoor_BAT_Bladabindi_N{
	meta:
		description = "Backdoor:BAT/Bladabindi.N,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 09 00 07 00 00 "
		
	strings :
		$a_01_0 = {5e 10 69 4c e4 41 60 d5 72 71 67 a2 d1 e4 03 3c 47 d4 04 4b fd 85 0d d2 6b b5 0a a5 fa a8 b5 35 6c 98 b2 42 d6 c9 bb db 40 f9 bc ac e3 6c d8 32 } //2
		$a_01_1 = {20 ac de 6c 27 20 85 46 b6 14 20 06 b0 ec 35 28 } //2
		$a_03_2 = {da d3 59 d3 59 d6 b3 69 ?? 38 [0-05] 38 [0-04] 02 7b [0-04] 03 6f } //2
		$a_00_3 = {64 64 62 35 66 66 64 37 36 65 31 30 34 35 30 65 39 32 33 35 36 39 61 62 30 30 65 32 63 32 31 39 } //2 ddb5ffd76e10450e923569ab00e2c219
		$a_00_4 = {73 65 72 76 65 72 2e 65 78 65 } //1 server.exe
		$a_00_5 = {70 61 73 73 77 6f 72 64 } //1 password
		$a_00_6 = {5c 4e 6f 75 76 65 61 75 } //1 \Nouveau
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2+(#a_03_2  & 1)*2+(#a_00_3  & 1)*2+(#a_00_4  & 1)*1+(#a_00_5  & 1)*1+(#a_00_6  & 1)*1) >=9
 
}