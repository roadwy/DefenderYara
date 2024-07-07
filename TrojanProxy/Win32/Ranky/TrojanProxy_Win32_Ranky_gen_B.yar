
rule TrojanProxy_Win32_Ranky_gen_B{
	meta:
		description = "TrojanProxy:Win32/Ranky.gen!B,SIGNATURE_TYPE_PEHSTR_EXT,0d 00 0a 00 05 00 00 "
		
	strings :
		$a_00_0 = {41 64 76 61 6e 63 65 64 20 44 48 54 4d 4c 20 45 6e 61 62 6c 65 } //1 Advanced DHTML Enable
		$a_00_1 = {48 54 54 50 2f 31 2e 30 20 32 30 30 20 43 6f 6e 6e 65 63 74 69 6f 6e 20 65 73 74 61 62 6c 69 73 68 65 64 } //1 HTTP/1.0 200 Connection established
		$a_00_2 = {48 54 54 50 2f 31 2e 30 20 32 30 31 20 55 6e 61 62 6c 65 20 74 6f 20 63 6f 6e 6e 65 63 74 } //1 HTTP/1.0 201 Unable to connect
		$a_03_3 = {f2 ae f7 d1 49 51 8d 4c 24 90 01 01 51 52 e8 90 01 04 8d 44 24 90 01 01 50 e8 90 01 04 83 c4 10 68 a0 bb 0d 00 ff d6 e9 90 00 } //10
		$a_03_4 = {99 b9 fd fb 00 00 f7 f9 81 c2 01 04 00 00 66 89 15 90 01 04 68 e8 03 00 00 ff d6 33 d2 66 8b 15 90 01 04 52 68 90 01 04 e8 90 01 04 83 c4 08 85 c0 75 c4 90 00 } //10
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_03_3  & 1)*10+(#a_03_4  & 1)*10) >=10
 
}