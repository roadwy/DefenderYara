
rule Ransom_MSIL_Filecoder_ARAD_MTB{
	meta:
		description = "Ransom:MSIL/Filecoder.ARAD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 03 00 00 "
		
	strings :
		$a_80_0 = {69 6e 73 65 72 74 20 79 6f 75 72 20 62 69 63 6f 69 6e 20 61 64 72 65 73 73 20 68 65 72 65 } //insert your bicoin adress here  2
		$a_80_1 = {68 6f 77 20 74 6f 20 72 65 6d 6f 76 65 20 63 72 79 70 74 6f 6c 6f 63 6b 65 72 } //how to remove cryptolocker  2
		$a_80_2 = {59 6f 75 72 20 50 65 72 73 6f 6e 61 6c 20 46 69 6c 65 73 20 41 72 65 20 45 6e 63 72 79 70 74 65 64 21 } //Your Personal Files Are Encrypted!  2
	condition:
		((#a_80_0  & 1)*2+(#a_80_1  & 1)*2+(#a_80_2  & 1)*2) >=6
 
}
rule Ransom_MSIL_Filecoder_ARAD_MTB_2{
	meta:
		description = "Ransom:MSIL/Filecoder.ARAD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 04 00 00 "
		
	strings :
		$a_80_0 = {43 4f 4c 49 4e 20 52 41 4e 53 4f 4d 57 41 52 45 } //COLIN RANSOMWARE  2
		$a_80_1 = {66 75 63 6b 75 6e 65 73 5f 66 61 63 65 } //fuckunes_face  2
		$a_80_2 = {62 69 6e 5c 52 75 6e 74 69 6d 65 42 72 6f 6b 65 72 50 59 2e 65 78 65 } //bin\RuntimeBrokerPY.exe  2
		$a_01_3 = {5c 45 6e 63 72 79 70 74 44 65 63 72 79 70 74 46 69 6c 65 73 5c 6f 62 6a 5c 44 65 62 75 67 5c 43 6f 6c 69 6e 77 61 72 65 2e 70 64 62 } //2 \EncryptDecryptFiles\obj\Debug\Colinware.pdb
	condition:
		((#a_80_0  & 1)*2+(#a_80_1  & 1)*2+(#a_80_2  & 1)*2+(#a_01_3  & 1)*2) >=8
 
}
rule Ransom_MSIL_Filecoder_ARAD_MTB_3{
	meta:
		description = "Ransom:MSIL/Filecoder.ARAD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 03 00 00 "
		
	strings :
		$a_80_0 = {5c 5f 5f 5f 52 45 43 4f 56 45 52 5f 5f 46 49 4c 45 53 5f 5f 2e 53 6f 6c 6f 67 79 2e 74 78 74 } //\___RECOVER__FILES__.Sology.txt  2
		$a_80_1 = {41 6c 6c 20 6f 66 20 79 6f 75 72 20 66 69 6c 65 73 20 68 61 76 65 20 62 65 65 6e 20 65 6e 63 72 79 70 74 65 64 2e } //All of your files have been encrypted.  2
		$a_80_2 = {33 31 68 53 57 6f 56 64 5a 4a 67 78 74 61 69 53 58 52 71 62 54 73 45 77 56 4e 77 32 76 76 43 51 74 59 } //31hSWoVdZJgxtaiSXRqbTsEwVNw2vvCQtY  2
	condition:
		((#a_80_0  & 1)*2+(#a_80_1  & 1)*2+(#a_80_2  & 1)*2) >=6
 
}