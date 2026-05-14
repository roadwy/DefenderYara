
rule Trojan_Win64_Keylogger_ARR_MTB{
	meta:
		description = "Trojan:Win64/Keylogger.ARR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,14 00 14 00 04 00 00 "
		
	strings :
		$a_81_0 = {53 74 65 61 6c 74 68 20 4b 65 79 6c 6f 67 67 65 72 20 53 74 61 72 74 65 64 20 28 46 69 78 65 64 20 56 65 72 73 69 6f 6e 29 } //10 Stealth Keylogger Started (Fixed Version)
		$a_81_1 = {42 52 4f 45 53 45 52 43 4f 4f 4b 49 45 2e 65 78 65 } //7 BROESERCOOKIE.exe
		$a_81_2 = {50 61 79 6c 6f 61 64 20 65 78 65 63 75 74 69 6f 6e 20 70 68 61 73 65 20 63 6f 6d 70 6c 65 74 65 64 } //2 Payload execution phase completed
		$a_81_3 = {42 72 6f 77 73 65 72 20 43 6f 6f 6b 69 65 20 53 74 65 61 6c 65 72 } //1 Browser Cookie Stealer
	condition:
		((#a_81_0  & 1)*10+(#a_81_1  & 1)*7+(#a_81_2  & 1)*2+(#a_81_3  & 1)*1) >=20
 
}