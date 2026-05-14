
rule Ransom_Linux_0APTLOCKER_A_MSR{
	meta:
		description = "Ransom:Linux/0APTLOCKER.A!MSR,SIGNATURE_TYPE_ELFHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {3a 3a 3a 20 30 41 50 54 20 4c 4f 43 4b 45 52 20 3a 3a 3a } //1 ::: 0APT LOCKER :::
		$a_01_1 = {52 45 41 44 4d 45 30 61 70 74 2e 74 78 74 } //1 README0apt.txt
		$a_01_2 = {65 6d 62 65 64 64 65 64 5f 77 61 6c 6c 70 61 70 65 72 2e 70 6e 67 } //1 embedded_wallpaper.png
		$a_01_3 = {89 f3 31 f6 31 c9 0f b6 3b 83 c7 d0 83 ff 09 0f 87 4b fe ff ff 89 55 ec 89 f0 ba 0a 00 00 00 01 c9 43 f7 e2 8d 0c 89 89 c6 01 fe 11 d1 8b 55 ec 4a } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}