
rule Trojan_Win64_Trickbot_STL{
	meta:
		description = "Trojan:Win64/Trickbot.STL,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 04 00 00 "
		
	strings :
		$a_02_0 = {2f 6c 69 66 65 2f 76 69 76 69 64 00 [0-40] 4c 4c 44 20 50 44 42 2e 01 00 00 00 63 6f 72 65 2e 70 64 62 } //2
		$a_02_1 = {5f 78 36 34 5f 72 75 6e 64 6c 6c 33 32 2e 64 6c 6c [0-20] 44 6c 6c 52 65 67 69 73 74 65 72 53 65 72 76 65 72 } //1
		$a_01_2 = {48 b8 f9 99 e8 9b f9 9d 9e 9f } //1
		$a_01_3 = {48 b8 97 98 8c 91 65 6d 31 31 } //1
	condition:
		((#a_02_0  & 1)*2+(#a_02_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=3
 
}