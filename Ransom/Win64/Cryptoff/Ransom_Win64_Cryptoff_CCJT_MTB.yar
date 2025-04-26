
rule Ransom_Win64_Cryptoff_CCJT_MTB{
	meta:
		description = "Ransom:Win64/Cryptoff.CCJT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 04 00 00 "
		
	strings :
		$a_03_0 = {48 8b c8 ff 15 ?? ?? ?? ?? e8 ?? ?? ?? ?? 4c 8d 35 ?? ?? 01 00 4c 89 75 c7 4c 8d 25 ?? ?? 01 00 4c 89 65 cf 0f 28 45 c7 66 0f 7f 45 c7 41 b1 01 [0-03] 48 8d 55 c7 e8 ?? ?? ?? ?? c7 45 67 50 00 bb 01 48 8d 45 67 48 89 45 c7 48 8d 45 6b 48 89 45 cf 0f 28 45 c7 66 0f 7f 45 c7 48 8d 55 c7 48 8d 4d e7 e8 } //5
		$a_01_1 = {53 4f 46 54 57 41 52 45 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 52 75 6e } //1 SOFTWARE\Microsoft\Windows\CurrentVersion\Run
		$a_01_2 = {53 65 6e 64 69 6e 67 20 72 65 71 75 65 73 74 20 66 6f 72 20 68 69 64 64 65 6e 20 73 65 72 76 69 63 65 20 64 65 73 63 72 69 70 74 6f 72 2e 2e 2e } //1 Sending request for hidden service descriptor...
		$a_01_3 = {48 69 64 64 65 6e 20 73 65 72 76 69 63 65 20 64 65 73 63 72 69 70 74 6f 72 20 72 65 63 65 69 76 65 64 2e 2e 2e } //1 Hidden service descriptor received...
	condition:
		((#a_03_0  & 1)*5+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=8
 
}