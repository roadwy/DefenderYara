
rule TrojanSpy_Win32_Banload_AAA_bit{
	meta:
		description = "TrojanSpy:Win32/Banload.AAA!bit,SIGNATURE_TYPE_PEHSTR_EXT,0f 00 0f 00 06 00 00 0a 00 "
		
	strings :
		$a_03_0 = {4b 85 db 7c 90 01 01 8b 45 f0 c1 e0 06 03 d8 89 5d f0 83 c7 06 83 ff 08 7c 90 01 01 83 ef 08 8b cf 8b 5d f0 d3 eb 8b cf b8 01 00 00 00 d3 e0 50 8b 45 f0 5a 8b ca 99 f7 f9 89 55 f0 81 e3 ff 00 00 80 79 08 4b 81 cb 00 ff ff ff 43 90 00 } //01 00 
		$a_01_1 = {8b 41 01 80 39 e9 74 0c 80 39 eb 75 0c 0f be c0 41 41 eb 03 83 c1 05 01 c1 } //01 00 
		$a_01_2 = {25 00 57 00 49 00 4e 00 44 00 49 00 52 00 25 00 5c 00 73 00 79 00 73 00 74 00 65 00 6d 00 33 00 32 00 5c 00 74 00 69 00 6d 00 65 00 6f 00 75 00 74 00 2e 00 65 00 78 00 65 00 20 00 33 00 20 00 26 00 20 00 64 00 65 00 6c 00 } //01 00  %WINDIR%\system32\timeout.exe 3 & del
		$a_01_3 = {25 00 54 00 45 00 4d 00 50 00 25 00 5c 00 63 00 75 00 72 00 62 00 75 00 66 00 2e 00 64 00 61 00 74 00 } //01 00  %TEMP%\curbuf.dat
		$a_01_4 = {55 48 4a 76 59 32 56 7a 63 32 39 79 54 6d 46 74 5a 56 4e 30 63 6d 6c 75 5a 77 3d 3d } //01 00  UHJvY2Vzc29yTmFtZVN0cmluZw==
		$a_01_5 = {52 47 6c 7a 63 47 78 68 65 56 5a 6c 63 6e 4e 70 62 32 34 3d } //00 00  RGlzcGxheVZlcnNpb24=
	condition:
		any of ($a_*)
 
}