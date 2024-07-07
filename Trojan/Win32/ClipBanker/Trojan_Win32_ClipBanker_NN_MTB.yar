
rule Trojan_Win32_ClipBanker_NN_MTB{
	meta:
		description = "Trojan:Win32/ClipBanker.NN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 04 00 00 "
		
	strings :
		$a_80_0 = {72 75 73 71 62 78 67 73 2e 30 30 30 77 65 62 68 6f 73 74 61 70 70 2e 63 6f 6d 2f 31 2e 74 78 74 } //rusqbxgs.000webhostapp.com/1.txt  5
		$a_80_1 = {72 65 67 20 61 64 64 20 48 4b 43 55 5c 53 4f 46 54 57 41 52 45 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 52 75 6e } //reg add HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Run  1
		$a_80_2 = {73 63 68 74 61 73 6b 73 2e 65 78 65 20 2f 63 72 65 61 74 65 20 2f 73 63 } //schtasks.exe /create /sc  1
		$a_80_3 = {63 6c 69 70 70 65 72 2d 31 2e 31 5c 52 65 6c 65 61 73 65 5c 63 6c 69 70 70 65 72 2d 31 2e 31 2e 70 64 62 } //clipper-1.1\Release\clipper-1.1.pdb  1
	condition:
		((#a_80_0  & 1)*5+(#a_80_1  & 1)*1+(#a_80_2  & 1)*1+(#a_80_3  & 1)*1) >=8
 
}