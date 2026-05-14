
rule Ransom_Win64_PClocked_SL_MTB{
	meta:
		description = "Ransom:Win64/PClocked.SL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 08 00 00 "
		
	strings :
		$a_81_0 = {2e 70 63 6c 6f 63 6b 65 64 } //1 .pclocked
		$a_81_1 = {52 65 64 42 6c 61 63 6b 43 68 6f 6f 73 65 20 79 6f 75 72 20 73 69 64 65 3a 53 70 69 6e 6e 69 6e 67 20 74 68 65 20 77 68 65 65 6c } //1 RedBlackChoose your side:Spinning the wheel
		$a_81_2 = {49 6e 76 61 6c 69 64 20 61 6d 6f 75 6e 74 2e 20 54 68 65 20 68 6f 75 73 65 20 64 6f 65 73 6e 27 74 20 74 61 6b 65 20 63 72 65 64 69 74 21 } //1 Invalid amount. The house doesn't take credit!
		$a_81_3 = {59 6f 75 20 61 72 65 20 62 61 6e 6b 72 75 70 74 21 20 47 61 6d 65 20 4f 76 65 72 } //1 You are bankrupt! Game Over
		$a_81_4 = {53 68 75 74 74 69 6e 67 20 64 6f 77 6e 20 65 6e 67 69 6e 65 2e 2e 2e 20 50 72 65 73 73 20 45 6e 74 65 72 20 74 6f 20 65 78 69 74 } //1 Shutting down engine... Press Enter to exit
		$a_81_5 = {72 75 6e 61 73 45 6c 65 76 61 74 69 6f 6e 20 72 65 71 75 65 73 74 20 66 61 69 6c 65 64 } //1 runasElevation request failed
		$a_81_6 = {76 73 73 61 64 6d 69 6e 64 65 6c 65 74 65 73 68 61 64 6f 77 73 2f 61 6c 6c 2f 71 75 69 65 74 45 72 72 6f 72 } //1 vssadmindeleteshadows/all/quietError
		$a_81_7 = {74 72 79 20 74 75 72 6e 69 6e 67 20 6f 66 66 20 79 6f 75 72 20 41 56 20 61 6e 64 20 72 65 72 75 6e 20 74 68 65 20 73 6f 66 74 77 61 72 65 } //1 try turning off your AV and rerun the software
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1+(#a_81_5  & 1)*1+(#a_81_6  & 1)*1+(#a_81_7  & 1)*1) >=8
 
}