
rule Trojan_BAT_Seraph_ASBA_MTB{
	meta:
		description = "Trojan:BAT/Seraph.ASBA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 08 00 00 01 00 "
		
	strings :
		$a_01_0 = {65 00 79 00 4a 00 75 00 59 00 57 00 31 00 6c 00 49 00 6a 00 6f 00 69 00 59 00 58 00 56 00 30 00 61 00 44 00 41 00 75 00 61 00 6e 00 4d 00 69 00 4c 00 43 00 4a 00 32 00 5a 00 58 00 4a 00 7a 00 61 00 57 00 39 00 75 00 49 00 6a 00 6f 00 69 00 4f 00 53 00 34 00 78 00 4d 00 43 00 34 00 30 00 49 00 6e 00 30 00 3d 00 } //01 00  eyJuYW1lIjoiYXV0aDAuanMiLCJ2ZXJzaW9uIjoiOS4xMC40In0=
		$a_01_1 = {4a 00 52 00 31 00 43 00 6f 00 54 00 4f 00 77 00 45 00 32 00 71 00 74 00 36 00 70 00 75 00 77 00 67 00 38 00 4f 00 77 00 4b 00 48 00 78 00 44 00 6b 00 56 00 6a 00 42 00 46 00 36 00 79 00 54 00 } //01 00  JR1CoTOwE2qt6puwg8OwKHxDkVjBF6yT
		$a_01_2 = {70 00 6f 00 72 00 6e 00 68 00 75 00 62 00 2e 00 63 00 6f 00 6d 00 2f 00 73 00 69 00 67 00 6e 00 75 00 70 00 } //01 00  pornhub.com/signup
		$a_01_3 = {44 00 6f 00 6d 00 61 00 69 00 6e 00 20 00 53 00 6f 00 72 00 74 00 65 00 72 00 2f 00 40 00 67 00 6d 00 78 00 2e 00 6e 00 65 00 74 00 2e 00 74 00 78 00 74 00 } //01 00  Domain Sorter/@gmx.net.txt
		$a_01_4 = {70 00 6f 00 72 00 6e 00 68 00 75 00 62 00 2e 00 63 00 6f 00 6d 00 2f 00 75 00 73 00 65 00 72 00 2f 00 63 00 72 00 65 00 61 00 74 00 65 00 5f 00 61 00 63 00 63 00 6f 00 75 00 6e 00 74 00 5f 00 63 00 68 00 65 00 63 00 6b 00 3f 00 74 00 6f 00 6b 00 65 00 6e 00 3d 00 4d 00 54 00 59 00 78 00 4e 00 7a 00 51 00 77 00 4d 00 54 00 59 00 32 00 4e 00 5f 00 70 00 75 00 41 00 4c 00 57 00 57 00 73 00 31 00 6a 00 50 00 47 00 42 00 66 00 5a 00 4c 00 41 00 56 00 47 00 7a 00 67 00 6c 00 47 00 53 00 56 00 45 00 } //01 00  pornhub.com/user/create_account_check?token=MTYxNzQwMTY2N_puALWWs1jPGBfZLAVGzglGSVE
		$a_01_5 = {4e 00 6f 00 74 00 20 00 52 00 65 00 67 00 69 00 73 00 74 00 65 00 72 00 65 00 64 00 2e 00 74 00 78 00 74 00 } //01 00  Not Registered.txt
		$a_01_6 = {3d 00 3d 00 3d 00 3d 00 3d 00 3d 00 3d 00 3d 00 3d 00 3d 00 3d 00 3d 00 3d 00 3d 00 3d 00 3d 00 3d 00 3d 00 3d 00 3d 00 53 00 55 00 42 00 53 00 3d 00 3d 00 3d 00 3d 00 3d 00 3d 00 3d 00 3d 00 3d 00 3d 00 3d 00 3d 00 3d 00 3d 00 3d 00 3d 00 3d 00 3d 00 } //01 00  ====================SUBS==================
		$a_01_7 = {44 00 65 00 6c 00 69 00 76 00 65 00 72 00 6f 00 6f 00 20 00 56 00 4d 00 } //00 00  Deliveroo VM
	condition:
		any of ($a_*)
 
}