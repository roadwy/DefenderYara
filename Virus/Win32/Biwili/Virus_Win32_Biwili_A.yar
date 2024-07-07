
rule Virus_Win32_Biwili_A{
	meta:
		description = "Virus:Win32/Biwili.A,SIGNATURE_TYPE_PEHSTR,02 00 02 00 04 00 00 "
		
	strings :
		$a_01_0 = {81 3b 7f 45 4c 46 75 05 e8 e5 03 00 00 ff 55 a5 ff 55 99 eb c5 ff 55 9d 8d a5 19 01 00 00 61 9d } //1
		$a_01_1 = {5b 43 41 50 5a 4c 4f 51 20 54 45 4b 4e 49 51 20 31 2e 30 5d } //1 [CAPZLOQ TEKNIQ 1.0]
		$a_01_2 = {33 d2 b6 20 03 ca 6a 5d 58 cd 80 b6 10 0b c0 75 3e 50 53 6a 01 6a 03 4a 03 ca f7 d2 23 ca 51 50 8b dc b0 5a cd 80 83 c4 18 3d 00 f0 ff ff } //1
		$a_01_3 = {66 81 3b 4d 5a 75 13 8b 73 3c 81 fe ff 0f 00 00 77 08 03 f3 81 3e 50 45 00 00 c3 66 81 7e 08 fb 7d 74 f7 8b 46 16 34 02 66 a9 02 20 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=2
 
}