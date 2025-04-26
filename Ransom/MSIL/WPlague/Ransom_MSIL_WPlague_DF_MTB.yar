
rule Ransom_MSIL_WPlague_DF_MTB{
	meta:
		description = "Ransom:MSIL/WPlague.DF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,10 00 10 00 05 00 00 "
		
	strings :
		$a_81_0 = {55 48 4a 76 61 6d 56 6a 64 45 5a 79 61 57 52 68 65 53 55 3d } //5 UHJvamVjdEZyaWRheSU=
		$a_81_1 = {50 72 6f 6a 65 63 74 46 72 69 64 61 79 } //5 ProjectFriday
		$a_81_2 = {46 72 6f 6d 42 61 73 65 36 34 53 74 72 69 6e 67 } //5 FromBase64String
		$a_81_3 = {5a 57 4d 32 4d 7a 4a 6d 5a 44 6b 74 4d 54 59 35 4e 43 30 30 5a 6a 52 68 4c 54 6c 69 5a 6d 59 74 5a 6a 49 77 4e 6a 41 77 5a 54 4d 33 4f 54 67 78 } //1 ZWM2MzJmZDktMTY5NC00ZjRhLTliZmYtZjIwNjAwZTM3OTgx
		$a_81_4 = {43 68 65 63 6b 52 65 6d 6f 74 65 44 65 62 75 67 67 65 72 50 72 65 73 65 6e 74 } //1 CheckRemoteDebuggerPresent
	condition:
		((#a_81_0  & 1)*5+(#a_81_1  & 1)*5+(#a_81_2  & 1)*5+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1) >=16
 
}