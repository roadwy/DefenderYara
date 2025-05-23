
rule PUA_Win32_MpTestPUAMapProd{
	meta:
		description = "PUA:Win32/MpTestPUAMapProd,SIGNATURE_TYPE_PEHSTR,0b 00 0a 00 05 00 00 "
		
	strings :
		$a_01_0 = {50 55 41 20 74 65 73 74 20 66 69 6c 65 20 4d 70 50 55 41 4d 61 70 50 72 6f 64 } //1 PUA test file MpPUAMapProd
		$a_01_1 = {49 6e 74 65 72 6e 61 6c 20 74 65 73 74 20 6f 6e 6c 79 21 20 44 6f 20 6e 6f 74 20 64 69 73 74 72 69 62 75 74 65 20 6f 75 74 73 69 64 65 20 79 6f 75 72 20 74 65 61 6d 21 } //1 Internal test only! Do not distribute outside your team!
		$a_01_2 = {64 39 33 37 61 37 33 64 2d 30 31 66 34 2d 34 36 30 66 2d 61 34 35 30 2d 64 39 33 63 35 32 35 66 35 39 32 62 } //3 d937a73d-01f4-460f-a450-d93c525f592b
		$a_01_3 = {34 38 36 63 65 62 63 30 2d 39 36 64 61 2d 34 38 34 66 2d 62 64 38 65 2d 31 66 33 30 62 39 63 32 32 34 35 65 } //3 486cebc0-96da-484f-bd8e-1f30b9c2245e
		$a_01_4 = {64 62 34 33 63 38 61 33 2d 61 37 64 35 2d 34 30 35 34 2d 38 34 61 36 2d 64 34 62 66 39 32 61 65 39 66 31 39 } //3 db43c8a3-a7d5-4054-84a6-d4bf92ae9f19
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*3+(#a_01_3  & 1)*3+(#a_01_4  & 1)*3) >=10
 
}