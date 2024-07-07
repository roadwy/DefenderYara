
rule Trojan_Win32_Qbot_DEC_MTB{
	meta:
		description = "Trojan:Win32/Qbot.DEC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 07 00 00 "
		
	strings :
		$a_81_0 = {4a 48 55 4b 72 77 4c 59 6b 46 } //1 JHUKrwLYkF
		$a_81_1 = {4e 59 75 77 6e 74 79 56 58 49 } //1 NYuwntyVXI
		$a_81_2 = {4b 42 76 4b 66 72 52 4d 56 67 } //1 KBvKfrRMVg
		$a_81_3 = {58 54 4f 6a 47 6f 51 65 50 67 } //1 XTOjGoQePg
		$a_81_4 = {44 79 79 57 57 75 77 4d 4e } //1 DyyWWuwMN
		$a_81_5 = {6c 47 64 7a 6f 55 70 4e 4c 51 } //1 lGdzoUpNLQ
		$a_81_6 = {48 46 69 77 78 74 4f 6f 57 78 } //1 HFiwxtOoWx
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1+(#a_81_5  & 1)*1+(#a_81_6  & 1)*1) >=5
 
}