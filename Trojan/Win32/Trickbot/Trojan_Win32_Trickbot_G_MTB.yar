
rule Trojan_Win32_Trickbot_G_MTB{
	meta:
		description = "Trojan:Win32/Trickbot.G!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_02_0 = {43 00 3a 00 5c 00 50 00 72 00 6f 00 67 00 72 00 61 00 6d 00 44 00 61 00 74 00 61 00 5c 00 90 02 30 2e 00 65 00 78 00 65 00 00 00 90 00 } //1
		$a_00_1 = {4b 4c 4f 45 44 53 57 41 58 } //1 KLOEDSWAX
		$a_00_2 = {43 4c 53 49 44 5c 25 31 5c 49 6e 50 72 6f 63 53 65 72 76 65 72 33 32 } //1 CLSID\%1\InProcServer32
		$a_00_3 = {25 32 5c 70 72 6f 74 6f 63 6f 6c 5c 53 74 64 46 69 6c 65 45 64 69 74 69 6e 67 5c 76 65 72 62 5c 30 } //1 %2\protocol\StdFileEditing\verb\0
		$a_00_4 = {43 57 69 6e 41 70 70 } //1 CWinApp
	condition:
		((#a_02_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1) >=5
 
}
rule Trojan_Win32_Trickbot_G_MTB_2{
	meta:
		description = "Trojan:Win32/Trickbot.G!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 02 00 00 "
		
	strings :
		$a_02_0 = {03 d0 8b 45 90 01 01 0f b6 14 10 8b 45 90 01 01 0f b6 0c 08 33 ca 8b 15 90 01 04 0f af 15 90 01 04 a1 90 01 04 0f af 05 90 01 04 0f af 05 90 01 04 0f af 05 90 01 04 8b 75 90 01 01 2b f0 03 f2 2b 35 90 01 04 2b 35 90 01 04 03 35 90 01 04 2b 35 90 01 04 8b 55 90 01 01 88 0c 32 e9 90 00 } //10
		$a_80_1 = {4b 56 74 37 71 4f 32 3c 77 7a 62 25 28 4b 31 30 24 64 31 6f 7a 35 21 38 77 79 59 23 74 36 5e 5a 71 46 71 50 30 79 4e 74 42 59 43 24 3c 68 77 51 4c 46 49 51 39 7a 78 50 34 73 48 6f 3f 71 25 55 3c 30 23 70 61 4c 47 49 3c 5e 66 53 43 25 2a } //KVt7qO2<wzb%(K10$d1oz5!8wyY#t6^ZqFqP0yNtBYC$<hwQLFIQ9zxP4sHo?q%U<0#paLGI<^fSC%*  10
	condition:
		((#a_02_0  & 1)*10+(#a_80_1  & 1)*10) >=10
 
}