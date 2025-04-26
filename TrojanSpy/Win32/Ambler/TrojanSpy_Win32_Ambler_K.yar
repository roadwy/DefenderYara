
rule TrojanSpy_Win32_Ambler_K{
	meta:
		description = "TrojanSpy:Win32/Ambler.K,SIGNATURE_TYPE_PEHSTR_EXT,05 00 04 00 06 00 00 "
		
	strings :
		$a_03_0 = {8b 45 08 8a 08 84 c9 74 08 80 f1 ?? 88 08 40 eb f2 } //2
		$a_03_1 = {2b fe 80 71 ff ?? 80 31 ?? 80 71 01 ?? 83 c1 03 83 c2 03 8d 1c 0f 3b d8 72 e8 } //2
		$a_08_2 = {5f 62 65 67 69 6e 74 68 72 65 61 64 65 78 } //1 _beginthreadex
		$a_08_3 = {48 74 74 70 53 65 6e 64 52 65 71 75 65 73 74 41 } //1 HttpSendRequestA
		$a_01_4 = {75 73 65 72 69 64 3d 25 73 } //1 userid=%s
		$a_01_5 = {3c 52 55 4e } //1 <RUN
	condition:
		((#a_03_0  & 1)*2+(#a_03_1  & 1)*2+(#a_08_2  & 1)*1+(#a_08_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=4
 
}