
rule Backdoor_Win32_Paras_B{
	meta:
		description = "Backdoor:Win32/Paras.B,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 05 00 00 "
		
	strings :
		$a_03_0 = {8a 1c 11 80 f3 11 88 1c 11 8b 55 ?? 80 04 11 89 } //2
		$a_01_1 = {99 b9 19 00 00 00 f7 f9 83 c2 61 52 } //1
		$a_02_2 = {b1 52 b0 75 c6 44 24 ?? 4c c6 44 24 ?? 6f c6 44 24 ?? 61 c6 44 24 ?? 64 } //1
		$a_00_3 = {5c 43 6f 6d 6d 6f 6e 20 46 69 6c 65 73 5c 33 36 30 6c 69 76 65 75 70 64 61 74 65 2e 64 6c 6c } //1 \Common Files\360liveupdate.dll
		$a_00_4 = {41 64 6d 69 6e 69 73 74 72 61 74 6f 72 5c a1 b8 bf aa ca bc a1 b9 b2 cb b5 a5 5c b3 cc d0 f2 5c c6 f4 b6 af 5c 90 01 05 5c 44 65 62 75 67 2e 64 6c 6c } //1
	condition:
		((#a_03_0  & 1)*2+(#a_01_1  & 1)*1+(#a_02_2  & 1)*1+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1) >=4
 
}