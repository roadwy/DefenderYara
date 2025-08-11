
rule Trojan_Win64_DLLHijack_DE_MTB{
	meta:
		description = "Trojan:Win64/DLLHijack.DE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_81_0 = {74 61 73 6b 6b 69 6c 6c 20 2f 46 20 2f 49 4d 20 6d 73 65 64 67 65 2e 65 78 65 } //1 taskkill /F /IM msedge.exe
		$a_81_1 = {6e 6f 74 65 2e 68 74 6d 6c } //1 note.html
		$a_81_2 = {72 61 6e 73 6f 6d 73 76 63 } //1 ransomsvc
		$a_81_3 = {73 74 61 72 74 2d 66 75 6c 6c 73 63 72 65 65 6e } //1 start-fullscreen
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1) >=4
 
}