
rule Ransom_MSIL_Filecoder_PF_MTB{
	meta:
		description = "Ransom:MSIL/Filecoder.PF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 06 00 00 "
		
	strings :
		$a_81_0 = {6c 6f 63 6b 65 64 2d 70 61 64 6c 6f 63 6b } //1 locked-padlock
		$a_81_1 = {44 69 73 61 62 6c 65 54 61 73 6b 4d 67 72 } //1 DisableTaskMgr
		$a_81_2 = {4c 6f 6f 6b 73 20 6c 69 6b 65 20 79 6f 75 72 20 66 69 6c 65 73 20 68 61 76 65 20 62 65 65 6e 20 65 6e 63 72 79 70 74 65 64 } //1 Looks like your files have been encrypted
		$a_81_3 = {5c 44 65 73 6b 74 6f 70 5c 52 45 41 44 4d 45 2e 74 78 74 } //1 \Desktop\README.txt
		$a_81_4 = {43 3a 5c 57 69 6e 64 6f 77 73 5c 4c 6f 67 73 5c 6b 65 6b 77 2e 65 78 65 } //1 C:\Windows\Logs\kekw.exe
		$a_81_5 = {68 74 74 70 73 3a 2f 2f 63 64 6e 2e 64 69 73 63 6f 72 64 61 70 70 2e 63 6f 6d 2f 61 74 74 61 63 68 6d 65 6e 74 73 2f 37 33 34 35 31 37 34 31 32 32 38 37 38 37 33 30 33 38 2f 37 34 36 30 38 38 30 32 32 33 35 36 39 31 38 34 36 33 2f } //1 https://cdn.discordapp.com/attachments/734517412287873038/746088022356918463/
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1+(#a_81_5  & 1)*1) >=5
 
}