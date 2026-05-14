
rule Ransom_Win64_ObesityLocker_AB_MTB{
	meta:
		description = "Ransom:Win64/ObesityLocker.AB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0c 00 0c 00 05 00 00 "
		
	strings :
		$a_81_0 = {59 6f 75 72 20 66 69 6c 65 73 20 61 72 65 20 65 6e 63 72 79 70 74 65 64 21 } //3 Your files are encrypted!
		$a_81_1 = {4f 42 45 53 49 54 59 20 4c 4f 43 4b 45 52 } //3 OBESITY LOCKER
		$a_81_2 = {25 73 5c 74 2e 6d 65 5f 65 75 78 61 6f 64 65 76 5f 25 64 5f 25 64 2e 74 78 74 } //2 %s\t.me_euxaodev_%d_%d.txt
		$a_81_3 = {25 73 77 61 6c 6c 70 61 70 65 72 5f 74 65 6d 70 2e 62 6d 70 } //2 %swallpaper_temp.bmp
		$a_81_4 = {53 6f 66 74 77 61 72 65 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 52 75 6e } //2 Software\Microsoft\Windows\CurrentVersion\Run
	condition:
		((#a_81_0  & 1)*3+(#a_81_1  & 1)*3+(#a_81_2  & 1)*2+(#a_81_3  & 1)*2+(#a_81_4  & 1)*2) >=12
 
}