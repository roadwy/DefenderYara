
rule Ransom_Win64_Filecoder_GGN_MTB{
	meta:
		description = "Ransom:Win64/Filecoder.GGN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 08 00 00 "
		
	strings :
		$a_01_0 = {47 6c 6f 62 61 6c 5c 52 61 6e 73 6f 6d 4c 6f 72 64 5f 32 30 32 35 } //1 Global\RansomLord_2025
		$a_01_1 = {76 73 73 61 64 6d 69 6e 20 64 65 6c 65 74 65 20 73 68 61 64 6f 77 73 20 2f 61 6c 6c 20 2f 71 75 69 65 74 } //1 vssadmin delete shadows /all /quiet
		$a_01_2 = {53 45 4e 44 20 50 52 4f 4f 46 20 54 4f 20 64 61 72 6b 77 65 62 5f 64 65 61 64 } //1 SEND PROOF TO darkweb_dead
		$a_01_3 = {59 4f 55 52 20 53 59 53 54 45 4d 20 49 53 20 41 4e 4e 49 48 49 4c 41 54 45 44 } //1 YOUR SYSTEM IS ANNIHILATED
		$a_01_4 = {73 63 20 73 74 6f 70 20 57 69 6e 44 65 66 65 6e 64 } //1 sc stop WinDefend
		$a_01_5 = {50 41 59 5f 55 50 2e 74 78 74 } //1 PAY_UP.txt
		$a_01_6 = {44 69 73 61 62 6c 65 41 6e 74 69 53 70 79 77 61 72 65 20 2f 74 20 52 45 47 5f 44 57 4f 52 44 20 2f 64 20 31 20 2f 66 } //1 DisableAntiSpyware /t REG_DWORD /d 1 /f
		$a_01_7 = {2e 65 6e 63 72 79 70 74 65 64 } //1 .encrypted
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1) >=8
 
}