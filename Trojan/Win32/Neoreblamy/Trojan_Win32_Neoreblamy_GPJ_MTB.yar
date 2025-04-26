
rule Trojan_Win32_Neoreblamy_GPJ_MTB{
	meta:
		description = "Trojan:Win32/Neoreblamy.GPJ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 03 00 00 "
		
	strings :
		$a_81_0 = {4e 6a 68 66 67 79 78 72 65 74 46 67 5a 78 4f 61 66 4f 4b 65 66 } //3 NjhfgyxretFgZxOafOKef
		$a_81_1 = {45 66 61 45 41 63 66 61 72 4a 54 48 70 } //2 EfaEAcfarJTHp
		$a_81_2 = {64 62 7a 6e 49 53 6a 68 61 74 78 42 46 4d 4f } //1 dbznISjhatxBFMO
	condition:
		((#a_81_0  & 1)*3+(#a_81_1  & 1)*2+(#a_81_2  & 1)*1) >=6
 
}
rule Trojan_Win32_Neoreblamy_GPJ_MTB_2{
	meta:
		description = "Trojan:Win32/Neoreblamy.GPJ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 03 00 00 "
		
	strings :
		$a_81_0 = {71 5a 77 57 6b 46 46 6e 69 6a 6e 6d 67 4c 71 4c 4c 67 72 6b 63 76 48 } //3 qZwWkFFnijnmgLqLLgrkcvH
		$a_81_1 = {53 4b 66 43 4a 78 45 43 62 65 45 6b 56 63 52 } //2 SKfCJxECbeEkVcR
		$a_81_2 = {64 55 58 48 48 6f 5a 65 74 4d 65 6f 43 6d 6a 6b 76 56 75 73 69 6c 64 65 4c } //1 dUXHHoZetMeoCmjkvVusildeL
	condition:
		((#a_81_0  & 1)*3+(#a_81_1  & 1)*2+(#a_81_2  & 1)*1) >=6
 
}