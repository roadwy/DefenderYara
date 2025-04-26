
rule Trojan_Win32_GuLoader_RBF_MTB{
	meta:
		description = "Trojan:Win32/GuLoader.RBF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 07 00 00 "
		
	strings :
		$a_81_0 = {41 74 72 69 65 72 6e 65 5c 55 6e 69 6e 73 74 61 6c 6c 5c 43 61 73 68 65 77 6e 64 64 65 72 6e 65 73 32 39 5c 75 6e 73 75 6d 6d 61 72 69 73 61 62 6c 65 } //1 Atrierne\Uninstall\Cashewnddernes29\unsummarisable
		$a_81_1 = {5c 61 6d 70 68 69 74 68 61 6c 61 6d 75 73 5c 69 6e 64 6b 61 6c 64 65 6c 73 65 73 64 61 67 65 6e 65 2e 64 6c 6c } //1 \amphithalamus\indkaldelsesdagene.dll
		$a_81_2 = {5c 63 61 6c 65 6e 64 61 72 69 61 6c 5c 77 61 62 62 6c 69 6e 67 6c 79 2e 55 6e 6f } //1 \calendarial\wabblingly.Uno
		$a_81_3 = {25 74 72 61 6e 73 70 6f 72 74 6d 69 64 6c 65 74 73 25 5c 62 65 73 6b 75 65 6c 73 65 73 2e 6d 61 72 } //1 %transportmidlets%\beskuelses.mar
		$a_81_4 = {70 61 72 69 65 74 6f 6a 75 67 61 6c } //1 parietojugal
		$a_81_5 = {63 68 6f 6d 70 65 72 73 20 6f 6b 6b 65 72 65 73 20 69 6e 63 6f 6e 64 69 74 69 6f 6e 65 64 } //1 chompers okkeres inconditioned
		$a_81_6 = {70 65 72 69 73 68 65 72 73 20 74 72 6f 6f 70 69 61 6c 73 20 62 6f 72 61 6b 73 } //1 perishers troopials boraks
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1+(#a_81_5  & 1)*1+(#a_81_6  & 1)*1) >=7
 
}