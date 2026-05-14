
rule Ransom_Win64_Filecoder_A_MSR{
	meta:
		description = "Ransom:Win64/Filecoder.A!MSR,SIGNATURE_TYPE_PEHSTR,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {2e 65 6e 63 72 79 70 74 65 64 } //1 .encrypted
		$a_01_1 = {6d 61 69 6e 2e 72 75 6e 45 6e 63 72 79 70 74 } //1 main.runEncrypt
		$a_01_2 = {6d 61 69 6e 2e 70 61 69 6e 74 52 61 6e 73 6f 6d } //1 main.paintRansom
		$a_01_3 = {6d 61 69 6e 2e 64 72 6f 70 52 61 6e 73 6f 6d 4e 6f 74 65 } //1 main.dropRansomNote
		$a_01_4 = {52 45 41 44 5f 4d 45 5f 4e 4f 57 2e 74 78 74 } //1 READ_ME_NOW.txt
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}