
rule Ransom_Win32_Ryuk_MTB{
	meta:
		description = "Ransom:Win32/Ryuk!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {24 70 61 73 73 77 6f 72 64 20 3d 20 27 } //1 $password = '
		$a_01_1 = {24 74 6f 72 6c 69 6e 6b 20 3d 20 27 } //1 $torlink = '
		$a_01_2 = {72 00 65 00 70 00 2e 00 65 00 78 00 65 00 } //1 rep.exe
		$a_01_3 = {52 00 45 00 50 00 } //1 REP
		$a_01_4 = {52 59 55 4b 54 4d } //1 RYUKTM
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}
rule Ransom_Win32_Ryuk_MTB_2{
	meta:
		description = "Ransom:Win32/Ryuk!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {24 70 61 73 73 77 6f 72 64 20 3d 20 27 } //1 $password = '
		$a_01_1 = {24 74 6f 72 6c 69 6e 6b 20 3d 20 27 } //1 $torlink = '
		$a_01_2 = {52 59 55 4b 54 4d } //1 RYUKTM
		$a_01_3 = {4e 74 64 6c 6c 2e 64 6c 6c } //1 Ntdll.dll
		$a_01_4 = {4e 74 51 75 65 72 79 49 6e 66 6f 72 6d 61 74 69 6f 6e 50 72 6f 63 65 73 73 } //1 NtQueryInformationProcess
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}
rule Ransom_Win32_Ryuk_MTB_3{
	meta:
		description = "Ransom:Win32/Ryuk!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {83 c0 01 89 45 90 01 01 8b 4d 90 01 01 3b 4d 90 01 01 7d 90 01 01 8b 45 90 01 01 99 f7 7d 90 01 01 8b 45 90 01 01 8b 0c 90 90 89 4d 90 01 01 8b 55 90 01 01 03 55 90 01 01 8a 02 88 45 90 01 01 60 33 c0 8a 45 90 01 01 33 c9 8b 4d 90 01 01 d2 c8 88 45 90 01 01 61 8b 4d 90 01 01 03 4d 90 01 01 8a 55 90 01 01 88 11 eb 90 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}