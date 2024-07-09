
rule PWS_Win32_Wowsteal_AK{
	meta:
		description = "PWS:Win32/Wowsteal.AK,SIGNATURE_TYPE_PEHSTR_EXT,21 00 21 00 07 00 00 "
		
	strings :
		$a_02_0 = {6a 10 50 6a 00 c7 45 e0 01 00 00 00 ff 75 fc c7 45 ec 02 00 00 00 ff 15 ?? ?? 00 10 85 c0 } //10
		$a_00_1 = {43 6f 6e 74 65 6e 74 2d 54 79 70 65 3a 20 61 70 70 6c 69 63 61 74 69 6f 6e 2f 78 2d 77 77 77 2d 66 6f 72 6d 2d 75 72 6c 65 6e 63 6f 64 65 64 } //10 Content-Type: application/x-www-form-urlencoded
		$a_00_2 = {2e 44 4c 4c 00 44 6c 6c 43 61 6e 55 6e 6c 6f 61 64 4e 6f 77 00 44 6c 6c 47 65 74 43 6c 61 73 73 4f 62 6a 65 63 74 } //10 䐮䱌䐀汬慃啮汮慯乤睯䐀汬敇䍴慬獳扏敪瑣
		$a_00_3 = {25 73 5c 57 54 46 5c 63 6f 6e 66 69 67 2e 77 74 66 } //1 %s\WTF\config.wtf
		$a_02_4 = {6c 6f 67 69 6e 90 05 06 01 00 46 46 58 69 } //1
		$a_00_5 = {73 65 63 72 65 74 51 75 65 73 74 69 6f 6e 41 6e 73 77 65 72 } //1 secretQuestionAnswer
		$a_00_6 = {5b 61 63 63 6f 75 6e 74 4e 61 6d 65 3a } //1 [accountName:
	condition:
		((#a_02_0  & 1)*10+(#a_00_1  & 1)*10+(#a_00_2  & 1)*10+(#a_00_3  & 1)*1+(#a_02_4  & 1)*1+(#a_00_5  & 1)*1+(#a_00_6  & 1)*1) >=33
 
}