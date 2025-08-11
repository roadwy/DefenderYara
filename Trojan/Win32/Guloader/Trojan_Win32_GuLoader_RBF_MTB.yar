
rule Trojan_Win32_GuLoader_RBF_MTB{
	meta:
		description = "Trojan:Win32/GuLoader.RBF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_81_0 = {46 6f 72 63 65 70 73 5c 72 65 73 74 69 67 6d 61 74 69 73 65 73 5c 54 6f 72 72 65 6e 63 65 } //1 Forceps\restigmatises\Torrence
		$a_81_1 = {5c 44 65 6c 65 67 65 72 65 74 73 31 34 34 5c 64 61 6d 70 6e 69 6e 67 65 72 6e 65 2e 6b 69 6c } //1 \Delegerets144\dampningerne.kil
		$a_81_2 = {5c 65 6e 74 65 72 6f 72 72 68 65 61 5c 6f 75 74 74 61 6b 65 2e 75 70 66 } //1 \enterorrhea\outtake.upf
		$a_81_3 = {25 74 79 70 65 62 65 74 65 67 6e 65 6c 73 65 72 73 25 5c 63 68 6c 6f 72 69 6e 61 74 6f 72 5c 66 6f 67 65 64 72 65 74 74 65 72 6e 65 } //1 %typebetegnelsers%\chlorinator\fogedretterne
		$a_81_4 = {6b 75 6e 73 74 67 64 6e 69 6e 67 65 72 73 20 6f 72 6b 65 73 74 65 72 67 72 61 76 65 6e 2e 65 78 65 } //1 kunstgdningers orkestergraven.exe
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1) >=5
 
}
rule Trojan_Win32_GuLoader_RBF_MTB_2{
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