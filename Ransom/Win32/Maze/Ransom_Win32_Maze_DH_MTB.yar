
rule Ransom_Win32_Maze_DH_MTB{
	meta:
		description = "Ransom:Win32/Maze.DH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {43 3a 5c 73 68 69 74 5c 67 61 76 6e 6f 2e 70 64 62 } //1 C:\shit\gavno.pdb
		$a_01_1 = {43 3a 5c 61 61 61 5f 54 6f 75 63 68 4d 65 4e 6f 74 5f 2e 74 78 74 } //1 C:\aaa_TouchMeNot_.txt
		$a_01_2 = {64 00 6b 00 61 00 72 00 74 00 69 00 6e 00 6b 00 61 00 2e 00 62 00 6d 00 70 00 } //1 dkartinka.bmp
		$a_01_3 = {56 00 69 00 74 00 61 00 6c 00 69 00 6b 00 72 00 65 00 6d 00 65 00 7a 00 20 00 64 00 65 00 74 00 65 00 63 00 74 00 6f 00 72 00 } //1 Vitalikremez detector
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}