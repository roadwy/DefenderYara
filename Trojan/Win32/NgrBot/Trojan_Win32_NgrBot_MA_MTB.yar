
rule Trojan_Win32_NgrBot_MA_MTB{
	meta:
		description = "Trojan:Win32/NgrBot.MA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 06 00 00 "
		
	strings :
		$a_03_0 = {69 c0 fd 43 03 00 05 c3 9e 26 00 a3 ?? ?? ?? ?? c1 f8 10 25 ff 7f 00 00 c3 } //1
		$a_03_1 = {99 b9 e8 03 00 00 f7 f9 81 c2 f4 01 00 00 0f af d6 52 ff 15 ?? ?? ?? ?? 68 ?? ?? ?? ?? 6a 00 68 01 00 1f 00 ff 15 } //1
		$a_01_2 = {66 72 6f 6d 20 72 65 6d 6f 76 69 6e 67 20 6f 75 72 20 62 6f 74 20 66 69 6c 65 21 } //1 from removing our bot file!
		$a_01_3 = {4d 65 73 73 61 67 65 20 68 69 6a 61 63 6b 65 64 21 } //1 Message hijacked!
		$a_01_4 = {2a 79 6f 75 70 6f 72 6e 2e 2a 2f 6c 6f 67 69 6e 2a } //1 *youporn.*/login*
		$a_01_5 = {6e 67 72 42 6f 74 } //1 ngrBot
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=5
 
}