
rule Trojan_Win32_Emotet_BT{
	meta:
		description = "Trojan:Win32/Emotet.BT,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 05 00 00 "
		
	strings :
		$a_01_0 = {50 62 37 33 30 2e 70 64 62 } //4 Pb730.pdb
		$a_01_1 = {73 4e 51 2e 70 64 62 } //4 sNQ.pdb
		$a_01_2 = {74 00 74 00 62 00 77 00 20 00 47 00 61 00 20 00 50 00 72 00 20 00 4e 00 55 00 63 00 77 00 62 00 6c 00 67 00 63 00 20 00 41 00 68 00 77 00 6d 00 20 00 4a 00 7a 00 62 00 } //2 ttbw Ga Pr NUcwblgc Ahwm Jzb
		$a_01_3 = {66 00 48 00 79 00 6b 00 59 00 74 00 20 00 55 00 7a 00 70 00 6e 00 50 00 72 00 20 00 58 00 55 00 43 00 53 00 70 00 20 00 4e 00 4f 00 6a 00 67 00 44 00 41 00 62 00 59 00 76 00 6d 00 20 00 55 00 4e 00 5a 00 44 00 20 00 41 00 41 00 } //2 fHykYt UzpnPr XUCSp NOjgDAbYvm UNZD AA
		$a_01_4 = {49 00 44 00 49 00 5f 00 44 00 55 00 4b 00 45 00 5f 00 49 00 43 00 4f 00 4e 00 } //1 IDI_DUKE_ICON
	condition:
		((#a_01_0  & 1)*4+(#a_01_1  & 1)*4+(#a_01_2  & 1)*2+(#a_01_3  & 1)*2+(#a_01_4  & 1)*1) >=7
 
}
rule Trojan_Win32_Emotet_BT_2{
	meta:
		description = "Trojan:Win32/Emotet.BT,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {62 00 72 00 65 00 48 00 45 00 52 00 56 00 57 00 72 00 6e 00 45 00 47 00 52 00 45 00 62 00 20 00 73 00 74 00 6f 00 70 00 20 00 7a 00 72 00 66 00 48 00 66 00 66 00 73 00 5a 00 47 00 65 00 48 00 20 00 5a 00 56 00 67 00 6c 00 74 00 64 00 6e 00 78 00 48 00 20 00 38 00 33 00 37 00 38 00 33 00 36 00 } //1 breHERVWrnEGREb stop zrfHffsZGeH ZVgltdnxH 837836
		$a_01_1 = {43 00 4b 00 76 00 2e 00 61 00 77 00 45 00 56 00 57 00 65 00 68 00 57 00 52 00 4e 00 57 00 52 00 20 00 4a 00 5a 00 28 00 6b 00 79 00 29 00 57 00 45 00 46 00 } //1 CKv.awEVWehWRNWR JZ(ky)WEF
		$a_01_2 = {6e 00 69 00 37 00 3d 00 38 00 68 00 4c 00 4f 00 36 00 6f 00 } //1 ni7=8hLO6o
		$a_01_3 = {2b 39 21 6d 79 44 30 69 59 35 21 75 73 73 75 5f 73 76 58 79 35 62 6e 69 38 4a 38 43 55 2e 70 64 62 } //1 +9!myD0iY5!ussu_svXy5bni8J8CU.pdb
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}