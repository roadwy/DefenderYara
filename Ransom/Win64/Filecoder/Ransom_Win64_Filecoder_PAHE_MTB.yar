
rule Ransom_Win64_Filecoder_PAHE_MTB{
	meta:
		description = "Ransom:Win64/Filecoder.PAHE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 03 00 00 "
		
	strings :
		$a_01_0 = {44 6b c1 1c b8 09 04 02 81 41 f7 e8 41 03 d0 c1 fa 06 8b c2 c1 e8 1f 03 d0 6b c2 7f 44 2b c0 41 83 c0 7f b8 09 04 02 81 41 f7 e8 41 03 d0 c1 fa 06 8b c2 c1 e8 } //2
		$a_00_1 = {3c 00 42 00 41 00 43 00 4b 00 55 00 50 00 5f 00 45 00 4d 00 41 00 49 00 4c 00 3e 00 } //1 <BACKUP_EMAIL>
		$a_00_2 = {3c 00 52 00 45 00 41 00 44 00 4d 00 45 00 5f 00 46 00 49 00 4c 00 45 00 4e 00 41 00 4d 00 45 00 3e 00 } //1 <README_FILENAME>
	condition:
		((#a_01_0  & 1)*2+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1) >=4
 
}