
rule Trojan_BAT_Bepush_B{
	meta:
		description = "Trojan:BAT/Bepush.B,SIGNATURE_TYPE_PEHSTR_EXT,1f 00 1f 00 05 00 00 "
		
	strings :
		$a_01_0 = {79 00 6f 00 6b 00 2e 00 74 00 78 00 74 00 } //1 yok.txt
		$a_01_1 = {76 00 61 00 72 00 2e 00 74 00 78 00 74 00 } //1 var.txt
		$a_01_2 = {5c 46 50 6c 61 79 2e 70 64 62 } //10 \FPlay.pdb
		$a_01_3 = {2f 00 69 00 6e 00 64 00 65 00 78 00 5f 00 73 00 74 00 61 00 72 00 74 00 2e 00 68 00 74 00 6d 00 6c 00 } //10 /index_start.html
		$a_03_4 = {08 09 8e 69 fe 04 13 09 11 09 3a a1 fe ff ff 7e 11 00 00 04 16 fe 01 13 09 11 09 2d 12 00 7e 08 00 00 04 72 ?? ?? 00 70 28 ?? 00 00 0a } //10
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*10+(#a_01_3  & 1)*10+(#a_03_4  & 1)*10) >=31
 
}
rule Trojan_BAT_Bepush_B_2{
	meta:
		description = "Trojan:BAT/Bepush.B,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 09 00 00 "
		
	strings :
		$a_01_0 = {63 68 72 6f 6d 65 56 61 72 4d 69 00 } //1 档潲敭慖䵲i
		$a_01_1 = {4b 69 6c 6c 43 68 72 6f 6d 65 00 } //1
		$a_01_2 = {52 00 65 00 67 00 20 00 64 00 65 00 6e 00 65 00 6d 00 65 00 2e 00 2e 00 2e 00 } //1 Reg deneme...
		$a_01_3 = {43 00 72 00 65 00 61 00 74 00 65 00 20 00 6c 00 6f 00 67 00 31 00 32 00 33 00 2e 00 2e 00 2e 00 } //1 Create log123...
		$a_01_4 = {2f 00 69 00 6e 00 64 00 65 00 78 00 5f 00 73 00 74 00 61 00 72 00 74 00 2e 00 68 00 74 00 6d 00 6c 00 } //1 /index_start.html
		$a_01_5 = {2f 00 79 00 6f 00 6b 00 2e 00 74 00 78 00 74 00 } //1 /yok.txt
		$a_01_6 = {43 00 68 00 72 00 6f 00 6d 00 65 00 20 00 65 00 78 00 74 00 65 00 6e 00 73 00 69 00 6f 00 6e 00 20 00 7b 00 30 00 7d 00 20 00 69 00 6e 00 73 00 74 00 61 00 6c 00 6c 00 65 00 64 00 2e 00 2e 00 2e 00 } //1 Chrome extension {0} installed...
		$a_01_7 = {45 00 78 00 74 00 65 00 6e 00 73 00 69 00 6f 00 6e 00 3a 00 20 00 7b 00 30 00 7d 00 20 00 64 00 6f 00 77 00 6e 00 6c 00 6f 00 61 00 64 00 2e 00 2e 00 2e 00 } //1 Extension: {0} download...
		$a_01_8 = {46 00 79 00 50 00 6c 00 61 00 79 00 65 00 72 00 30 00 31 00 2e 00 50 00 72 00 6f 00 70 00 65 00 72 00 74 00 69 00 65 00 73 00 } //1 FyPlayer01.Properties
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1+(#a_01_8  & 1)*1) >=8
 
}