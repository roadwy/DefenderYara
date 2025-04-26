
rule Ransom_Win32_Filecoder_BF_MTB{
	meta:
		description = "Ransom:Win32/Filecoder.BF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 04 00 00 "
		
	strings :
		$a_81_0 = {2f 63 20 76 73 73 61 64 6d 69 6e 2e 65 78 65 20 44 65 6c 65 74 65 20 53 68 61 64 6f 77 73 20 2f 41 6c 6c 20 2f 51 75 69 65 74 } //2 /c vssadmin.exe Delete Shadows /All /Quiet
		$a_81_1 = {41 6c 6c 20 79 6f 75 72 20 66 69 6c 65 73 20 68 61 76 65 20 62 65 65 6e 20 65 6e 63 72 79 70 74 65 64 20 62 79 20 75 73 } //2 All your files have been encrypted by us
		$a_81_2 = {48 6f 77 20 52 65 63 6f 76 65 72 79 20 46 69 6c 65 73 2e 74 78 74 } //1 How Recovery Files.txt
		$a_81_3 = {49 66 20 79 6f 75 20 77 61 6e 74 20 72 65 73 74 6f 72 65 20 66 69 6c 65 73 20 77 72 69 74 65 20 6f 6e 20 65 2d 6d 61 69 6c 20 2d 20 6a 69 6d 6d 79 6e 65 79 74 72 6f 6e 40 74 75 74 61 2e 69 6f } //1 If you want restore files write on e-mail - jimmyneytron@tuta.io
	condition:
		((#a_81_0  & 1)*2+(#a_81_1  & 1)*2+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1) >=5
 
}