
rule Ransom_Linux_JumpScare_A{
	meta:
		description = "Ransom:Linux/JumpScare.A,SIGNATURE_TYPE_ELFHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {55 48 89 e5 89 7d fc 89 75 f8 8b 45 f8 33 45 fc f7 d0 89 45 fc 8b 45 fc c1 e0 10 21 45 fc 8b 45 fc c1 e0 08 21 45 fc 8b 45 fc c1 e0 04 21 45 fc 8b 45 fc c1 e0 02 21 45 fc 8b 45 fc 01 c0 21 45 fc 8b 45 fc c1 f8 1f c9 c3 } //2
		$a_01_1 = {8b 45 f4 48 c1 e0 03 48 03 45 e8 48 8b 00 89 c2 8b 45 f4 48 c1 e0 03 48 03 45 e0 48 8b 00 31 d0 23 45 f8 89 45 fc 8b 45 f4 48 c1 e0 03 48 89 c2 48 03 55 e8 8b 45 f4 48 c1 e0 03 48 03 45 e8 48 8b 00 33 45 fc 48 98 48 89 02 8b 45 f4 48 c1 e0 03 48 89 c2 48 03 55 e0 8b 45 f4 48 c1 e0 03 48 03 45 e0 48 8b 00 33 45 fc 48 98 48 89 02 83 45 f4 01 } //2
		$a_01_2 = {2e 6d 61 72 69 6f } //1 .mario
		$a_01_3 = {2f 48 6f 77 20 54 6f 20 52 65 73 74 6f 72 65 20 59 6f 75 72 20 46 69 6c 65 73 2e 74 78 74 } //1 /How To Restore Your Files.txt
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}