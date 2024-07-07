
rule Trojan_BAT_SqlBrute_A_MTB{
	meta:
		description = "Trojan:BAT/SqlBrute.A!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 06 00 00 "
		
	strings :
		$a_81_0 = {77 69 6e 6c 6f 67 6f 6e 2e 70 64 62 } //1 winlogon.pdb
		$a_81_1 = {73 61 40 31 32 33 34 35 36 } //1 sa@123456
		$a_81_2 = {65 78 65 63 20 73 70 5f 70 61 73 73 77 6f 72 64 20 6e 75 6c 6c 2c 27 20 31 32 33 21 23 40 41 42 43 61 62 63 27 2c 27 77 65 62 73 61 27 } //1 exec sp_password null,' 123!#@ABCabc','websa'
		$a_81_3 = {65 78 65 63 20 73 70 5f 70 61 73 73 77 6f 72 64 20 6e 75 6c 6c 2c 27 20 31 32 33 21 23 40 41 42 43 61 62 63 27 2c 27 36 64 6f 6f 72 27 } //1 exec sp_password null,' 123!#@ABCabc','6door'
		$a_81_4 = {77 69 6e 6c 6f 67 6f 6e 2e 52 65 73 6f 75 72 63 65 73 2e 73 71 6c 41 64 6d 69 6e 2e 74 78 74 } //1 winlogon.Resources.sqlAdmin.txt
		$a_81_5 = {77 69 6e 6c 6f 67 6f 6e 2e 52 65 73 6f 75 72 63 65 73 2e 73 71 6c 4d 73 73 71 6c 2e 74 78 74 } //1 winlogon.Resources.sqlMssql.txt
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1+(#a_81_5  & 1)*1) >=6
 
}