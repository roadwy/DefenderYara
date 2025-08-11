
rule Ransom_Win64_Filecoder_MKQ_MTB{
	meta:
		description = "Ransom:Win64/Filecoder.MKQ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 07 00 00 "
		
	strings :
		$a_01_0 = {44 69 73 61 62 6c 65 20 46 69 72 65 77 61 6c 6c } //1 Disable Firewall
		$a_01_1 = {45 6e 63 72 79 70 74 20 61 6c 6c 20 66 69 6c 65 73 } //1 Encrypt all files
		$a_01_2 = {21 21 21 20 57 41 52 4e 49 4e 47 3a 20 52 41 4e 53 4f 4d 57 41 52 45 20 44 45 54 45 43 54 45 44 20 21 21 21 } //1 !!! WARNING: RANSOMWARE DETECTED !!!
		$a_01_3 = {56 49 52 55 53 20 44 45 54 45 43 54 45 44 21 20 50 41 59 20 54 4f 20 52 45 4d 4f 56 45 21 } //1 VIRUS DETECTED! PAY TO REMOVE!
		$a_01_4 = {72 61 6e 73 6f 6d 5f 6e 6f 74 65 2e 74 78 74 } //1 ransom_note.txt
		$a_01_5 = {2e 65 6e 63 72 79 70 74 65 64 } //1 .encrypted
		$a_01_6 = {59 6f 75 72 20 50 43 20 69 73 20 46 55 43 4b 45 44 } //1 Your PC is FUCKED
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1) >=7
 
}