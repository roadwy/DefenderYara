
rule Trojan_Win32_Emotet_SP_MSR{
	meta:
		description = "Trojan:Win32/Emotet.SP!MSR,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {66 00 41 00 6b 00 65 00 4c 00 4a 00 6d 00 72 00 56 00 47 00 71 00 6f 00 42 00 33 00 48 00 46 00 51 00 } //1 fAkeLJmrVGqoB3HFQ
		$a_01_1 = {62 6c 69 74 7a 5f 74 65 78 74 75 72 65 73 2f 74 6f 70 32 2e 74 67 61 } //1 blitz_textures/top2.tga
		$a_01_2 = {50 72 6f 67 72 61 6d 20 57 69 6c 6c 20 4e 6f 77 20 43 6c 6f 73 65 } //1 Program Will Now Close
		$a_01_3 = {53 65 74 46 6f 72 65 67 72 6f 75 6e 64 57 69 6e 64 6f 77 } //1 SetForegroundWindow
		$a_01_4 = {53 48 55 54 44 4f 57 4e 20 45 52 52 4f 52 } //1 SHUTDOWN ERROR
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}
rule Trojan_Win32_Emotet_SP_MSR_2{
	meta:
		description = "Trojan:Win32/Emotet.SP!MSR,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 04 00 00 "
		
	strings :
		$a_01_0 = {36 00 36 00 36 00 36 00 36 00 36 00 55 00 64 00 65 00 74 00 61 00 69 00 6c 00 73 00 67 00 4b 00 69 00 6e 00 74 00 6f 00 32 00 35 00 62 00 72 00 6f 00 77 00 73 00 65 00 72 00 77 00 } //1 666666UdetailsgKinto25browserw
		$a_01_1 = {66 00 69 00 72 00 73 00 74 00 64 00 69 00 63 00 6b 00 68 00 65 00 61 00 64 00 73 00 75 00 70 00 70 00 6f 00 72 00 74 00 } //1 firstdickheadsupport
		$a_01_2 = {72 00 65 00 6c 00 65 00 61 00 73 00 65 00 73 00 76 00 61 00 63 00 61 00 6e 00 63 00 79 00 61 00 64 00 64 00 72 00 65 00 73 00 73 00 62 00 72 00 6f 00 77 00 73 00 65 00 72 00 } //1 releasesvacancyaddressbrowser
		$a_01_3 = {42 7a 43 4b 79 5a 2d 69 73 6f 54 44 69 44 62 59 2e 4b 62 4d 6a 51 77 2e 70 64 62 } //1 BzCKyZ-isoTDiDbY.KbMjQw.pdb
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=2
 
}