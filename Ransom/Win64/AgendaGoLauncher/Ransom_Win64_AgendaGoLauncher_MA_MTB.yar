
rule Ransom_Win64_AgendaGoLauncher_MA_MTB{
	meta:
		description = "Ransom:Win64/AgendaGoLauncher.MA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {43 00 3a 00 5c 00 55 00 73 00 65 00 72 00 73 00 5c 00 50 00 75 00 62 00 6c 00 69 00 63 00 5c 00 65 00 6e 00 63 00 2e 00 65 00 78 00 65 00 } //1 C:\Users\Public\enc.exe
		$a_01_1 = {5c 52 65 6c 65 61 73 65 5c 70 77 6e 64 6c 6c 2e 70 64 62 } //1 \Release\pwndll.pdb
		$a_03_2 = {48 8d 44 24 50 45 33 c9 48 89 44 24 48 48 8d 0d 90 01 04 48 8d 44 24 70 45 33 c0 48 89 44 24 40 33 d2 48 c7 44 24 38 00 00 00 00 48 c7 44 24 30 00 00 00 00 c7 44 24 28 20 00 00 00 c7 44 24 20 00 00 00 00 ff 15 90 00 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_03_2  & 1)*1) >=3
 
}