
rule Ransom_Win64_Filecoder_GV_MTB{
	meta:
		description = "Ransom:Win64/Filecoder.GV!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0e 00 0e 00 06 00 00 "
		
	strings :
		$a_01_0 = {52 45 41 44 4d 45 2e 74 78 74 } //5 README.txt
		$a_01_1 = {2e 6f 6e 69 6f 6e } //5 .onion
		$a_01_2 = {6d 61 69 6e 2e 65 72 61 73 65 } //1 main.erase
		$a_01_3 = {6d 61 69 6e 2e 64 6f 45 6e 63 72 79 70 74 } //1 main.doEncrypt
		$a_01_4 = {6f 73 2e 28 2a 50 72 6f 63 65 73 73 29 2e 6b 69 6c 6c } //1 os.(*Process).kill
		$a_01_5 = {6d 61 69 6e 2e 52 75 6e } //1 main.Run
	condition:
		((#a_01_0  & 1)*5+(#a_01_1  & 1)*5+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=14
 
}