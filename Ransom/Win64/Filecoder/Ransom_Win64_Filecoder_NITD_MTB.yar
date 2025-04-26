
rule Ransom_Win64_Filecoder_NITD_MTB{
	meta:
		description = "Ransom:Win64/Filecoder.NITD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 05 00 00 "
		
	strings :
		$a_01_0 = {63 72 79 70 74 5f 6f 6e 6c 79 5f 74 68 65 73 65 5f 64 69 72 65 63 74 6f 72 69 65 73 } //2 crypt_only_these_directories
		$a_01_1 = {73 65 72 76 69 63 65 73 5f 74 6f 5f 73 74 6f 70 } //2 services_to_stop
		$a_01_2 = {63 65 73 5f 74 6f 5f 73 74 6f 70 } //2 ces_to_stop
		$a_01_3 = {74 65 6d 70 6f 72 61 72 79 5f 65 78 74 65 6e 73 69 6f 6e } //1 temporary_extension
		$a_01_4 = {6f 6e 69 6f 6e 2f 63 68 61 74 } //1 onion/chat
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2+(#a_01_2  & 1)*2+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=7
 
}
rule Ransom_Win64_Filecoder_NITD_MTB_2{
	meta:
		description = "Ransom:Win64/Filecoder.NITD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,10 00 10 00 0b 00 00 "
		
	strings :
		$a_01_0 = {46 49 4c 45 53 20 48 41 56 45 20 42 45 45 4e 20 45 4e 43 52 59 50 54 45 44 } //2 FILES HAVE BEEN ENCRYPTED
		$a_01_1 = {42 69 74 63 6f 69 6e } //2 Bitcoin
		$a_01_2 = {4e 4f 54 20 41 4c 4c 4f 57 20 41 4e 54 49 2d 56 49 52 55 53 20 53 4f 46 54 57 41 52 45 } //2 NOT ALLOW ANTI-VIRUS SOFTWARE
		$a_01_3 = {44 45 43 52 59 50 54 49 4e 47 20 41 4c 4c 20 46 49 4c 45 53 20 49 4d 50 4f 53 53 49 42 4c 45 } //2 DECRYPTING ALL FILES IMPOSSIBLE
		$a_01_4 = {72 65 63 65 69 76 65 20 79 6f 75 72 20 64 65 63 72 79 70 74 69 6f 6e 20 6b 65 79 } //2 receive your decryption key
		$a_01_5 = {65 6e 63 72 79 70 74 69 6f 6e 5f 64 61 74 65 } //1 encryption_date
		$a_01_6 = {54 6f 20 72 65 63 6f 76 65 72 20 79 6f 75 72 20 66 69 6c 65 73 } //1 To recover your files
		$a_01_7 = {56 69 72 74 75 61 6c 42 6f 78 } //1 VirtualBox
		$a_01_8 = {76 62 6f 78 74 72 61 79 } //1 vboxtray
		$a_01_9 = {76 62 6f 78 73 65 72 76 69 63 65 } //1 vboxservice
		$a_01_10 = {76 6d 74 6f 6f 6c 73 64 } //1 vmtoolsd
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2+(#a_01_2  & 1)*2+(#a_01_3  & 1)*2+(#a_01_4  & 1)*2+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1+(#a_01_8  & 1)*1+(#a_01_9  & 1)*1+(#a_01_10  & 1)*1) >=16
 
}