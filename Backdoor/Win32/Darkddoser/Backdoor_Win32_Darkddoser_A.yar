
rule Backdoor_Win32_Darkddoser_A{
	meta:
		description = "Backdoor:Win32/Darkddoser.A,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {48 54 54 50 20 46 6c 6f 6f 64 20 41 63 74 69 76 65 } //2 HTTP Flood Active
		$a_03_1 = {ba 01 20 00 00 e8 90 01 02 ff ff 6a 00 68 01 20 00 00 57 8b 43 04 50 e8 90 01 02 ff ff 90 01 02 eb 90 00 } //1
		$a_03_2 = {66 c7 43 08 02 00 0f b7 07 50 e8 90 01 02 ff ff 66 89 43 0a 8d 4d fc 90 00 } //1
		$a_01_3 = {64 61 72 6b 64 64 6f 73 65 72 } //1 darkddoser
		$a_01_4 = {53 59 4e 20 46 6c 6f 6f 64 20 41 63 74 69 76 65 } //1 SYN Flood Active
	condition:
		((#a_01_0  & 1)*2+(#a_03_1  & 1)*1+(#a_03_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}