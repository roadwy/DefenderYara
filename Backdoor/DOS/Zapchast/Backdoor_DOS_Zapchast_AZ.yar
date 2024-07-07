
rule Backdoor_DOS_Zapchast_AZ{
	meta:
		description = "Backdoor:DOS/Zapchast.AZ,SIGNATURE_TYPE_PEHSTR,2a 00 2a 00 07 00 00 "
		
	strings :
		$a_01_0 = {43 3a 5c 52 45 43 59 43 4c 45 52 5c 53 2d 31 2d 35 2d 32 31 2d 36 30 36 37 34 37 31 34 35 2d 31 30 38 35 30 33 31 32 31 34 2d 37 32 35 33 34 35 35 34 33 2d 35 30 30 5c 73 75 70 2e 65 78 65 } //10 C:\RECYCLER\S-1-5-21-606747145-1085031214-725345543-500\sup.exe
		$a_01_1 = {61 5f 66 72 69 65 6e 64 2e 65 78 65 } //10 a_friend.exe
		$a_01_2 = {6d 69 72 63 2e 69 6e 69 } //10 mirc.ini
		$a_01_3 = {75 73 65 72 73 2e 69 6e 69 } //10 users.ini
		$a_01_4 = {70 6f 70 75 70 73 2e 74 78 74 } //1 popups.txt
		$a_01_5 = {4e 65 63 61 7a 75 6c 2e 75 73 65 72 73 2e 75 6e 64 65 72 6e 65 74 2e 6f 72 67 31 } //1 Necazul.users.undernet.org1
		$a_01_6 = {73 65 72 76 65 72 73 2e 69 6e 69 } //1 servers.ini
	condition:
		((#a_01_0  & 1)*10+(#a_01_1  & 1)*10+(#a_01_2  & 1)*10+(#a_01_3  & 1)*10+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1) >=42
 
}