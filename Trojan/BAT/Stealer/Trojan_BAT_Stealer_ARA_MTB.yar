
rule Trojan_BAT_Stealer_ARA_MTB{
	meta:
		description = "Trojan:BAT/Stealer.ARA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 02 00 00 "
		
	strings :
		$a_01_0 = {62 68 63 77 79 6a 68 77 77 36 63 73 39 67 7a 6a 6a 6a 63 76 79 75 70 6c 67 70 34 70 61 38 74 6c } //2 bhcwyjhww6cs9gzjjjcvyuplgp4pa8tl
		$a_01_1 = {4d 61 72 6b 64 69 67 2e 52 65 73 6f 6c 76 65 72 } //2 Markdig.Resolver
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2) >=4
 
}
rule Trojan_BAT_Stealer_ARA_MTB_2{
	meta:
		description = "Trojan:BAT/Stealer.ARA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 04 00 00 "
		
	strings :
		$a_01_0 = {5c 53 74 69 6c 6c 65 72 52 6f 6c 74 6f 6e 2e 70 64 62 } //2 \StillerRolton.pdb
		$a_00_1 = {73 00 65 00 6c 00 65 00 63 00 74 00 20 00 2a 00 20 00 66 00 72 00 6f 00 6d 00 20 00 6c 00 6f 00 67 00 69 00 6e 00 73 00 } //2 select * from logins
		$a_00_2 = {70 00 61 00 73 00 73 00 77 00 6f 00 72 00 64 00 5f 00 76 00 61 00 6c 00 75 00 65 00 } //2 password_value
		$a_00_3 = {75 00 73 00 65 00 72 00 6e 00 61 00 6d 00 65 00 5f 00 76 00 61 00 6c 00 75 00 65 00 } //2 username_value
	condition:
		((#a_01_0  & 1)*2+(#a_00_1  & 1)*2+(#a_00_2  & 1)*2+(#a_00_3  & 1)*2) >=8
 
}
rule Trojan_BAT_Stealer_ARA_MTB_3{
	meta:
		description = "Trojan:BAT/Stealer.ARA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 04 00 00 "
		
	strings :
		$a_80_0 = {43 3a 5c 55 73 65 72 73 5c 41 68 6d 65 64 5c 44 6f 63 75 6d 65 6e 74 73 5c 56 69 73 75 61 6c 20 53 74 75 64 69 6f 20 32 30 31 30 5c 50 72 6f 6a 65 63 74 73 5c 70 6c 61 5c 42 6f 6f 74 6d 67 72 5c 6f 62 6a 5c 78 38 36 5c 44 65 62 75 67 5c 42 6f 6f 74 6d 67 72 2e 70 64 62 } //C:\Users\Ahmed\Documents\Visual Studio 2010\Projects\pla\Bootmgr\obj\x86\Debug\Bootmgr.pdb  2
		$a_80_1 = {43 3a 5c 42 6f 6f 74 5c 42 6f 6f 74 6d 67 72 2e 63 6f 6d } //C:\Boot\Bootmgr.com  2
		$a_80_2 = {63 3a 5c 62 6f 6f 74 5c 6d 65 2e 64 6c 6c } //c:\boot\me.dll  2
		$a_80_3 = {6c 6f 67 2e 74 78 74 } //log.txt  2
	condition:
		((#a_80_0  & 1)*2+(#a_80_1  & 1)*2+(#a_80_2  & 1)*2+(#a_80_3  & 1)*2) >=8
 
}