
rule Ransom_Win64_FileCoder_CQ_MTB{
	meta:
		description = "Ransom:Win64/FileCoder.CQ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_81_0 = {53 74 61 72 74 69 6e 67 20 48 65 75 72 69 73 74 69 63 2f 53 74 61 74 69 63 20 41 56 20 54 65 73 74 20 28 31 30 30 25 25 20 48 61 72 6d 6c 65 73 73 29 } //1 Starting Heuristic/Static AV Test (100%% Harmless)
		$a_81_1 = {59 6f 75 72 20 66 69 6c 65 73 20 68 61 76 65 20 62 65 65 6e 20 65 6e 63 72 79 70 74 65 64 21 } //1 Your files have been encrypted!
		$a_81_2 = {53 75 73 70 69 63 69 6f 75 73 20 73 74 72 69 6e 67 73 20 61 72 65 20 6c 6f 61 64 65 64 2e } //1 Suspicious strings are loaded.
		$a_81_3 = {5b 2b 5d 20 44 72 6f 70 70 65 64 20 45 49 43 41 52 20 74 65 73 74 20 66 69 6c 65 20 74 6f 20 64 69 73 6b 2e } //1 [+] Dropped EICAR test file to disk.
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1) >=4
 
}