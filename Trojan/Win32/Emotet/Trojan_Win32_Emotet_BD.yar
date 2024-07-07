
rule Trojan_Win32_Emotet_BD{
	meta:
		description = "Trojan:Win32/Emotet.BD,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 03 00 00 "
		
	strings :
		$a_01_0 = {3d 71 63 35 76 34 32 33 34 76 35 5c 5c 32 33 76 34 35 32 33 34 5c 5c 32 32 33 34 35 76 32 33 34 35 2e 37 52 75 2e 70 64 62 } //1 =qc5v4234v5\\23v45234\\22345v2345.7Ru.pdb
		$a_01_1 = {63 69 54 66 44 43 78 4d 51 55 30 61 35 2f 44 44 45 79 47 77 6e 38 74 61 2e 7a 34 2e 70 64 62 } //1 ciTfDCxMQU0a5/DDEyGwn8ta.z4.pdb
		$a_01_2 = {37 6c 61 49 52 2b 7c 2e 58 4a 35 61 41 30 61 61 2e 70 64 62 } //1 7laIR+|.XJ5aA0aa.pdb
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=1
 
}
rule Trojan_Win32_Emotet_BD_2{
	meta:
		description = "Trojan:Win32/Emotet.BD,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_00_0 = {42 00 72 00 61 00 6e 00 63 00 68 00 73 00 75 00 70 00 65 00 72 00 6d 00 61 00 6e 00 6d 00 61 00 64 00 73 00 32 00 30 00 31 00 35 00 7a 00 63 00 68 00 65 00 6c 00 73 00 65 00 61 00 65 00 } //1 Branchsupermanmads2015zchelseae
		$a_00_1 = {6f 00 75 00 74 00 43 00 68 00 72 00 6f 00 6d 00 65 00 38 00 55 00 43 00 68 00 72 00 6f 00 6d 00 65 00 6c 00 55 00 } //1 outChrome8UChromelU
		$a_01_2 = {62 72 6f 77 73 65 72 73 2e 36 32 70 62 61 73 69 73 2e 38 35 36 4a 75 6e 64 65 72 37 4f } //1 browsers.62pbasis.856Junder7O
		$a_00_3 = {6f 00 66 00 66 00 6c 00 69 00 6e 00 65 00 63 00 6f 00 6d 00 70 00 6c 00 65 00 74 00 65 00 6c 00 79 00 42 00 65 00 74 00 61 00 4b 00 34 00 69 00 6d 00 70 00 6c 00 65 00 6d 00 65 00 6e 00 74 00 65 00 64 00 66 00 6f 00 72 00 } //1 offlinecompletelyBetaK4implementedfor
		$a_01_4 = {65 78 70 6c 6f 69 74 73 43 68 72 6f 6d 65 74 } //1 exploitsChromet
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_01_2  & 1)*1+(#a_00_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}