
rule Trojan_Win32_Relnicar_A_dha{
	meta:
		description = "Trojan:Win32/Relnicar.A!dha,SIGNATURE_TYPE_PEHSTR_EXT,14 00 14 00 02 00 00 "
		
	strings :
		$a_00_0 = {77 73 63 2e 64 6c 6c 00 5f 72 75 6e 40 34 00 } //10
		$a_03_1 = {b9 69 00 00 00 66 89 0c 45 90 02 04 68 00 00 00 80 b9 6f 00 00 00 68 90 02 04 66 89 0c 45 90 00 } //10
	condition:
		((#a_00_0  & 1)*10+(#a_03_1  & 1)*10) >=20
 
}
rule Trojan_Win32_Relnicar_A_dha_2{
	meta:
		description = "Trojan:Win32/Relnicar.A!dha,SIGNATURE_TYPE_PEHSTR,1e 00 1e 00 03 00 00 "
		
	strings :
		$a_01_0 = {53 69 64 3a 25 73 0d 0a 55 73 65 72 3a 25 73 0d 0a 43 6f 6d 70 75 74 65 72 3a 25 73 } //10
		$a_01_1 = {4c 61 6e 20 69 70 3a 25 73 0d 0a 55 72 6c 31 3a 25 73 20 } //10
		$a_01_2 = {65 78 70 61 6e 64 2e 65 78 65 20 2d 46 3a 2a 20 22 25 73 22 } //10 expand.exe -F:* "%s"
	condition:
		((#a_01_0  & 1)*10+(#a_01_1  & 1)*10+(#a_01_2  & 1)*10) >=30
 
}
rule Trojan_Win32_Relnicar_A_dha_3{
	meta:
		description = "Trojan:Win32/Relnicar.A!dha,SIGNATURE_TYPE_PEHSTR,1e 00 1e 00 03 00 00 "
		
	strings :
		$a_01_0 = {5c 00 77 00 73 00 63 00 2e 00 69 00 63 00 6f 00 2e 00 54 00 4d 00 50 00 } //10 \wsc.ico.TMP
		$a_01_1 = {5c 00 52 00 45 00 4d 00 4f 00 56 00 45 00 44 00 49 00 53 00 4b 00 5c 00 } //10 \REMOVEDISK\
		$a_01_2 = {73 65 73 73 69 6f 6e 74 68 3d 25 64 3b 20 75 69 64 74 68 3d 25 64 3b 20 63 6f 64 65 74 68 3d 25 64 3b 20 73 69 7a 65 74 68 3d 25 64 3b 20 6c 65 6e 67 74 68 3d 25 64 3b } //10 sessionth=%d; uidth=%d; codeth=%d; sizeth=%d; length=%d;
	condition:
		((#a_01_0  & 1)*10+(#a_01_1  & 1)*10+(#a_01_2  & 1)*10) >=30
 
}
rule Trojan_Win32_Relnicar_A_dha_4{
	meta:
		description = "Trojan:Win32/Relnicar.A!dha!!Relnicar.gen!A,SIGNATURE_TYPE_ARHSTR_EXT,1e 00 1e 00 03 00 00 "
		
	strings :
		$a_00_0 = {53 69 64 3a 25 73 0d 0a 55 73 65 72 3a 25 73 0d 0a 43 6f 6d 70 75 74 65 72 3a 25 73 } //10
		$a_00_1 = {4c 61 6e 20 69 70 3a 25 73 0d 0a 55 72 6c 31 3a 25 73 20 } //10
		$a_00_2 = {65 78 70 61 6e 64 2e 65 78 65 20 2d 46 3a 2a 20 22 25 73 22 } //10 expand.exe -F:* "%s"
	condition:
		((#a_00_0  & 1)*10+(#a_00_1  & 1)*10+(#a_00_2  & 1)*10) >=30
 
}
rule Trojan_Win32_Relnicar_A_dha_5{
	meta:
		description = "Trojan:Win32/Relnicar.A!dha!!Relnicar.gen!B,SIGNATURE_TYPE_ARHSTR_EXT,14 00 14 00 02 00 00 "
		
	strings :
		$a_00_0 = {77 73 63 2e 64 6c 6c 00 5f 72 75 6e 40 34 00 } //10
		$a_03_1 = {b9 69 00 00 00 66 89 0c 45 90 02 04 68 00 00 00 80 b9 6f 00 00 00 68 90 02 04 66 89 0c 45 90 00 } //10
	condition:
		((#a_00_0  & 1)*10+(#a_03_1  & 1)*10) >=20
 
}
rule Trojan_Win32_Relnicar_A_dha_6{
	meta:
		description = "Trojan:Win32/Relnicar.A!dha!!Relnicar.gen!C,SIGNATURE_TYPE_ARHSTR_EXT,1e 00 1e 00 03 00 00 "
		
	strings :
		$a_00_0 = {5c 00 77 00 73 00 63 00 2e 00 69 00 63 00 6f 00 2e 00 54 00 4d 00 50 00 } //10 \wsc.ico.TMP
		$a_00_1 = {5c 00 52 00 45 00 4d 00 4f 00 56 00 45 00 44 00 49 00 53 00 4b 00 5c 00 } //10 \REMOVEDISK\
		$a_00_2 = {73 65 73 73 69 6f 6e 74 68 3d 25 64 3b 20 75 69 64 74 68 3d 25 64 3b 20 63 6f 64 65 74 68 3d 25 64 3b 20 73 69 7a 65 74 68 3d 25 64 3b 20 6c 65 6e 67 74 68 3d 25 64 3b } //10 sessionth=%d; uidth=%d; codeth=%d; sizeth=%d; length=%d;
	condition:
		((#a_00_0  & 1)*10+(#a_00_1  & 1)*10+(#a_00_2  & 1)*10) >=30
 
}