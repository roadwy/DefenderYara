
rule Trojan_Win32_Tofsee_RW_MTB{
	meta:
		description = "Trojan:Win32/Tofsee.RW!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0d 00 0d 00 04 00 00 "
		
	strings :
		$a_81_0 = {3c 3c 46 49 4c 45 53 3a 25 64 20 20 20 49 4e 4a 45 43 54 3a 25 64 3e 3e } //10 <<FILES:%d   INJECT:%d>>
		$a_81_1 = {49 4e 4a 45 43 54 20 4f 4b 20 20 20 25 73 } //1 INJECT OK   %s
		$a_81_2 = {49 4e 4a 45 43 54 20 46 41 49 4c 20 25 73 } //1 INJECT FAIL %s
		$a_81_3 = {63 3a 5c 77 69 6e 64 6f 77 73 5c 64 65 62 75 67 } //1 c:\windows\debug
	condition:
		((#a_81_0  & 1)*10+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1) >=13
 
}