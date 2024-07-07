
rule TrojanSpy_Win32_Posokap_A_bit{
	meta:
		description = "TrojanSpy:Win32/Posokap.A!bit,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {00 4b 41 50 54 4f 58 41 00 } //1
		$a_01_1 = {6f 73 63 61 6e 20 70 72 6f 63 65 73 73 20 77 69 74 68 20 70 69 64 20 66 6f 72 20 6b 61 72 74 6f 78 61 } //1 oscan process with pid for kartoxa
		$a_01_2 = {5c 6d 6d 6f 6e 2e 70 64 62 00 } //2
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*2) >=3
 
}