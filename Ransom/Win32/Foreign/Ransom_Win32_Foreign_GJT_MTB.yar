
rule Ransom_Win32_Foreign_GJT_MTB{
	meta:
		description = "Ransom:Win32/Foreign.GJT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_80_0 = {5c 41 70 70 44 61 74 61 5c 52 6f 61 6d 69 6e 67 5c 4d 69 63 72 6f 73 6f 66 74 5c 4f 66 66 69 63 65 5c 4d 69 63 72 6f 73 6f 66 74 48 2e 65 78 65 } //\AppData\Roaming\Microsoft\Office\MicrosoftH.exe  1
		$a_80_1 = {53 4f 46 54 57 41 52 45 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 52 75 6e } //SOFTWARE\Microsoft\Windows\CurrentVersion\Run  1
		$a_01_2 = {5c 5a 5f 50 43 5c 73 6f 75 72 63 65 5c 72 65 70 6f 73 5c 52 65 70 6f 73 5c 52 65 6c 65 61 73 65 5c 6e 6f 72 6d 61 6c 6c 2e 70 64 62 } //1 \Z_PC\source\repos\Repos\Release\normall.pdb
		$a_01_3 = {2e 72 64 61 74 61 24 76 6f 6c 74 6d 64 } //1 .rdata$voltmd
		$a_01_4 = {2e 72 64 61 74 61 24 7a 7a 7a 64 62 67 } //1 .rdata$zzzdbg
	condition:
		((#a_80_0  & 1)*1+(#a_80_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}