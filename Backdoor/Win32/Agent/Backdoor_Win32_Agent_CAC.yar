
rule Backdoor_Win32_Agent_CAC{
	meta:
		description = "Backdoor:Win32/Agent.CAC,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {81 7d f4 30 15 00 00 73 19 8b 4d f4 33 d2 8a 91 88 11 b8 72 83 f2 19 8b 45 f4 88 90 88 11 b8 72 eb d5 } //1
		$a_01_1 = {0f 84 36 01 00 00 c6 85 54 fd ff ff 65 c6 85 55 fd ff ff 78 c6 85 56 fd ff ff 70 c6 85 57 fd ff ff 6c c6 85 58 fd ff ff 6f } //1
		$a_01_2 = {c6 85 d4 fe ff ff 77 c6 85 d5 fe ff ff 69 c6 85 d6 fe ff ff 6e c6 85 d7 fe ff ff 73 c6 85 d8 fe ff ff 74 c6 85 d9 fe ff ff 61 c6 85 da fe ff ff 30 c6 85 db fe ff ff 00 } //1
		$a_01_3 = {c6 45 ac 41 c6 45 ad 64 c6 45 ae 76 c6 45 af 61 c6 45 b0 70 c6 45 b1 69 c6 45 b2 33 c6 45 b3 32 c6 45 b4 2e c6 45 b5 64 c6 45 b6 6c c6 45 b7 6c c6 45 b8 00 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}