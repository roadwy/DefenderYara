
rule Trojan_Win64_CobaltStrike_DLR_MTB{
	meta:
		description = "Trojan:Win64/CobaltStrike.DLR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 05 00 00 "
		
	strings :
		$a_01_0 = {c7 44 24 20 40 00 00 00 41 b9 00 30 00 00 49 89 d0 ba 00 00 00 00 48 89 c1 48 8b 05 66 6a 00 00 ff d0 } //2
		$a_01_1 = {6d 61 73 6b 64 65 73 6b 2e 69 6e 66 6f } //1 maskdesk.info
		$a_01_2 = {2f 66 69 6c 65 } //1 /file
		$a_01_3 = {52 65 73 75 6d 65 54 68 72 65 61 64 } //1 ResumeThread
		$a_01_4 = {53 79 73 74 65 6d 33 32 5c 6e 6f 74 65 70 61 64 2e 65 78 65 } //1 System32\notepad.exe
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=6
 
}