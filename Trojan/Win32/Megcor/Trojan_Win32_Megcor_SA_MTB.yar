
rule Trojan_Win32_Megcor_SA_MTB{
	meta:
		description = "Trojan:Win32/Megcor.SA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 07 00 00 "
		
	strings :
		$a_81_0 = {21 2d 21 5f 52 45 41 44 4d 45 5f 21 2d 21 2e 72 74 66 } //1 !-!_README_!-!.rtf
		$a_81_1 = {5b 2b 5d 20 73 74 61 72 74 65 64 3a } //1 [+] started:
		$a_81_2 = {2e 63 6d 64 20 25 31 25 20 63 69 70 68 65 72 20 77 6d 69 63 } //1 .cmd %1% cipher wmic
		$a_81_3 = {5b 2b 5d 20 69 73 53 61 6e 62 6f 78 65 64 } //1 [+] isSanboxed
		$a_81_4 = {5b 2b 5d 20 70 72 6f 63 65 73 73 69 6e 67 } //1 [+] processing
		$a_81_5 = {64 65 6c 20 2f 51 20 2f 46 } //1 del /Q /F
		$a_81_6 = {65 63 68 6f 20 65 63 68 6f 20 2a 2a 2a 2a 2a 2a 2a 2a 2a 2a 2a 2a 2a 2a 2a 2a 2a 2a 2a 2a 2a 2a 2a 2a 2a 2a 2a 2a 2a 2a 2a 2a 2a 2a 2a 2a 2a 2a 2a 2a 2a 2a 2a 2a 2a 2a 2a 2a 2a 2a 2a 2a 2a 2a 2a 2a 2a 2a 2a 2a 2a 2a 2a 2a 2a 2a 2a 2a 2a 2a 2a 2a 2a 2a 20 3e 3e } //1 echo echo ************************************************************************** >>
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1+(#a_81_5  & 1)*1+(#a_81_6  & 1)*1) >=6
 
}