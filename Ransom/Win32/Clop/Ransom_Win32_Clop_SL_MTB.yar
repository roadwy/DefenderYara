
rule Ransom_Win32_Clop_SL_MTB{
	meta:
		description = "Ransom:Win32/Clop.SL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 06 00 00 "
		
	strings :
		$a_81_0 = {25 73 2e 43 6c 6c 70 } //1 %s.Cllp
		$a_81_1 = {2d 72 75 6e 72 75 6e } //1 -runrun
		$a_81_2 = {74 65 6d 70 2e 64 61 74 } //1 temp.dat
		$a_81_3 = {2d 2d 2d 2d 2d 42 45 47 49 4e 20 50 55 42 4c 49 43 20 4b 45 59 2d 2d 2d 2d 2d } //1 -----BEGIN PUBLIC KEY-----
		$a_81_4 = {2f 43 20 76 73 73 61 64 6d 69 6e 20 44 65 6c 65 74 65 20 53 68 61 64 6f 77 73 20 2f 61 6c 6c 20 2f 71 75 69 65 74 } //1 /C vssadmin Delete Shadows /all /quiet
		$a_81_5 = {25 73 5c 52 45 41 44 4d 45 5f 52 45 41 44 4d 45 2e 74 78 74 } //1 %s\README_README.txt
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1+(#a_81_5  & 1)*1) >=6
 
}