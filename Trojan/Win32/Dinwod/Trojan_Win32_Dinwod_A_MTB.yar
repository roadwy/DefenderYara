
rule Trojan_Win32_Dinwod_A_MTB{
	meta:
		description = "Trojan:Win32/Dinwod.A!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 07 00 00 "
		
	strings :
		$a_00_0 = {0f af 37 46 89 30 8b 09 8b 74 24 0c 8b 06 0f b7 4c 8a 02 } //1
		$a_00_1 = {32 06 5f 66 0f b6 c8 0f b7 c9 01 0e 8b 13 8b 75 14 8d 54 96 fc 01 0a } //1
		$a_80_2 = {62 74 6c 63 2e 64 61 74 } //btlc.dat  1
		$a_80_3 = {28 6b 69 73 73 29 } //(kiss)  1
		$a_80_4 = {77 68 61 74 20 74 68 65 20 66 75 63 6b 20 69 73 20 74 68 61 74 } //what the fuck is that  1
		$a_80_5 = {63 72 61 7a 79 20 62 69 74 63 68 } //crazy bitch  1
		$a_80_6 = {6e 69 63 65 20 61 73 73 3a 2a } //nice ass:*  1
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_80_2  & 1)*1+(#a_80_3  & 1)*1+(#a_80_4  & 1)*1+(#a_80_5  & 1)*1+(#a_80_6  & 1)*1) >=7
 
}