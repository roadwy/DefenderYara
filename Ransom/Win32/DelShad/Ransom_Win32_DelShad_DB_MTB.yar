
rule Ransom_Win32_DelShad_DB_MTB{
	meta:
		description = "Ransom:Win32/DelShad.DB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,09 00 09 00 06 00 00 "
		
	strings :
		$a_81_0 = {2f 63 20 76 73 73 61 64 6d 69 6e 2e 65 78 65 20 64 65 6c 65 74 65 20 73 68 61 64 6f 77 73 20 2f 61 6c 6c } //2 /c vssadmin.exe delete shadows /all
		$a_81_1 = {44 61 74 61 20 72 65 63 6f 76 65 72 79 2e 68 74 61 } //2 Data recovery.hta
		$a_81_2 = {46 69 6e 64 46 69 72 73 74 46 69 6c 65 41 } //2 FindFirstFileA
		$a_81_3 = {46 69 6e 64 4e 65 78 74 46 69 6c 65 41 } //2 FindNextFileA
		$a_81_4 = {40 74 75 74 61 6e 6f 74 61 2e 63 6f 6d } //1 @tutanota.com
		$a_81_5 = {40 70 72 6f 74 6f 6e 6d 61 69 6c 2e 63 6f 6d } //1 @protonmail.com
	condition:
		((#a_81_0  & 1)*2+(#a_81_1  & 1)*2+(#a_81_2  & 1)*2+(#a_81_3  & 1)*2+(#a_81_4  & 1)*1+(#a_81_5  & 1)*1) >=9
 
}