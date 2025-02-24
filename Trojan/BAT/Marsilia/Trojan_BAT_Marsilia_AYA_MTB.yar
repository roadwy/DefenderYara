
rule Trojan_BAT_Marsilia_AYA_MTB{
	meta:
		description = "Trojan:BAT/Marsilia.AYA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 05 00 00 "
		
	strings :
		$a_01_0 = {24 39 66 39 66 31 32 37 32 2d 38 39 32 66 2d 34 31 32 37 2d 61 63 39 33 2d 36 62 33 38 35 34 33 34 62 30 36 34 } //2 $9f9f1272-892f-4127-ac93-6b385434b064
		$a_01_1 = {55 73 65 72 73 5c 41 44 4d 49 4e 5c 73 6f 75 72 63 65 5c 72 65 70 6f 73 5c 66 75 64 64 64 32 5c 66 75 64 64 64 32 5c 6f 62 6a 5c 52 65 6c 65 61 73 65 } //1 Users\ADMIN\source\repos\fuddd2\fuddd2\obj\Release
		$a_00_2 = {2f 00 73 00 63 00 20 00 6f 00 6e 00 6c 00 6f 00 67 00 6f 00 6e 00 20 00 2f 00 72 00 6c 00 20 00 68 00 69 00 67 00 68 00 65 00 73 00 74 00 } //1 /sc onlogon /rl highest
		$a_01_3 = {44 6f 77 6e 6c 6f 61 64 46 69 6c 65 } //1 DownloadFile
		$a_01_4 = {47 65 74 52 61 6e 64 6f 6d 46 69 6c 65 4e 61 6d 65 } //1 GetRandomFileName
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*1+(#a_00_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=6
 
}