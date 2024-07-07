
rule Trojan_Win32_Dridex_NC_MTB{
	meta:
		description = "Trojan:Win32/Dridex.NC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {89 11 8b e5 5d c3 90 09 30 00 ff 90 02 05 8f 90 02 05 33 90 02 05 c7 05 90 02 08 8b 90 02 03 01 15 90 02 04 8b 0d 90 02 04 8b 15 90 00 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}
rule Trojan_Win32_Dridex_NC_MTB_2{
	meta:
		description = "Trojan:Win32/Dridex.NC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,12 00 12 00 06 00 00 "
		
	strings :
		$a_81_0 = {43 6f 6d 65 57 6f 6f 64 5c 46 61 72 6d 71 75 6f 74 69 65 6e 74 61 6e 73 77 65 72 2e 70 64 62 } //3 ComeWood\Farmquotientanswer.pdb
		$a_81_1 = {5c 4e 65 77 44 6f 63 74 6f 72 5c 73 74 65 61 64 4a 75 6d 70 } //3 \NewDoctor\steadJump
		$a_81_2 = {45 78 69 74 4d 61 69 6e 56 69 61 43 52 54 } //3 ExitMainViaCRT
		$a_81_3 = {44 65 63 6f 64 65 50 6f 69 6e 74 65 72 } //3 DecodePointer
		$a_81_4 = {53 65 74 45 6e 64 4f 66 46 69 6c 65 } //3 SetEndOfFile
		$a_81_5 = {53 79 73 74 65 6d 46 75 6e 63 74 69 6f 6e 30 33 36 } //3 SystemFunction036
	condition:
		((#a_81_0  & 1)*3+(#a_81_1  & 1)*3+(#a_81_2  & 1)*3+(#a_81_3  & 1)*3+(#a_81_4  & 1)*3+(#a_81_5  & 1)*3) >=18
 
}