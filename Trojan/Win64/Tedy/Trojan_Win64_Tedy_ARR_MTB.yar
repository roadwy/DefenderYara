
rule Trojan_Win64_Tedy_ARR_MTB{
	meta:
		description = "Trojan:Win64/Tedy.ARR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 02 00 00 "
		
	strings :
		$a_01_0 = {41 0f b6 08 48 33 c1 41 02 c9 80 e1 } //6
		$a_01_1 = {48 8b d0 0f b6 c9 48 d3 c2 48 33 c2 } //4
	condition:
		((#a_01_0  & 1)*6+(#a_01_1  & 1)*4) >=10
 
}
rule Trojan_Win64_Tedy_ARR_MTB_2{
	meta:
		description = "Trojan:Win64/Tedy.ARR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 02 00 00 "
		
	strings :
		$a_03_0 = {4c 0f 47 44 24 ?? 4c 8b 4c 24 ?? 49 ff c1 4c 89 7c 24 ?? 48 8b d0 48 8b ce } //8
		$a_81_1 = {7a 65 74 72 65 78 6f 61 2d 63 72 65 61 74 65 } //2 zetrexoa-create
	condition:
		((#a_03_0  & 1)*8+(#a_81_1  & 1)*2) >=10
 
}
rule Trojan_Win64_Tedy_ARR_MTB_3{
	meta:
		description = "Trojan:Win64/Tedy.ARR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,14 00 14 00 02 00 00 "
		
	strings :
		$a_03_0 = {8b c7 ff c7 48 8d 49 ?? 83 e0 07 0f b6 04 10 30 41 ff 41 3b f9 72 } //15
		$a_81_1 = {33 41 44 30 35 35 37 35 2d 38 38 35 37 2d 34 38 35 30 2d 39 32 37 37 2d 31 31 42 38 35 42 44 42 38 45 30 39 } //5 3AD05575-8857-4850-9277-11B85BDB8E09
	condition:
		((#a_03_0  & 1)*15+(#a_81_1  & 1)*5) >=20
 
}
rule Trojan_Win64_Tedy_ARR_MTB_4{
	meta:
		description = "Trojan:Win64/Tedy.ARR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,14 00 14 00 03 00 00 "
		
	strings :
		$a_03_0 = {4c 0f af f2 49 31 de c4 c3 fb f0 c5 ?? 48 0f af c2 4c 01 f7 } //10
		$a_03_1 = {41 8b 44 24 ?? 89 df 48 01 f7 83 c3 } //2
		$a_03_2 = {41 0f b7 4d 14 48 8d 04 0f 8b 54 0f ?? 39 da 77 } //8
	condition:
		((#a_03_0  & 1)*10+(#a_03_1  & 1)*2+(#a_03_2  & 1)*8) >=20
 
}
rule Trojan_Win64_Tedy_ARR_MTB_5{
	meta:
		description = "Trojan:Win64/Tedy.ARR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,14 00 14 00 02 00 00 "
		
	strings :
		$a_01_0 = {48 2b c8 0f b6 44 0c 30 43 32 04 10 41 88 00 4c 3b ce } //16
		$a_81_1 = {62 79 70 61 73 73 5c 62 79 70 61 73 73 2d 61 67 65 6e 74 5f 32 5c 77 6f 72 6b 73 70 61 63 65 5c 73 73 76 61 67 65 6e 74 5f 6d 75 6c 74 69 5f 78 6f 72 5f } //4 bypass\bypass-agent_2\workspace\ssvagent_multi_xor_
	condition:
		((#a_01_0  & 1)*16+(#a_81_1  & 1)*4) >=20
 
}
rule Trojan_Win64_Tedy_ARR_MTB_6{
	meta:
		description = "Trojan:Win64/Tedy.ARR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,14 00 14 00 03 00 00 "
		
	strings :
		$a_03_0 = {01 d0 0f be 51 ?? 01 d0 41 31 c0 4c 39 c9 } //2
		$a_01_1 = {4e 35 7a 68 61 6e 67 31 32 65 6e 63 79 70 74 69 6f 6e 41 6c 67 49 4c 79 36 34 45 45 45 } //8 N5zhang12encyptionAlgILy64EEE
		$a_01_2 = {4e 35 7a 68 61 6e 67 31 33 64 65 73 45 6e 63 72 79 70 74 69 6f 6e 45 } //10 N5zhang13desEncryptionE
	condition:
		((#a_03_0  & 1)*2+(#a_01_1  & 1)*8+(#a_01_2  & 1)*10) >=20
 
}
rule Trojan_Win64_Tedy_ARR_MTB_7{
	meta:
		description = "Trojan:Win64/Tedy.ARR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,1e 00 1e 00 05 00 00 "
		
	strings :
		$a_01_0 = {46 61 6c 68 61 20 61 6f 20 62 61 69 78 61 72 20 70 61 79 6c 6f 61 64 20 64 6f 20 53 71 75 61 72 65 57 65 62 } //4 Falha ao baixar payload do SquareWeb
		$a_01_1 = {5b 2a 5d 20 42 61 69 78 61 6e 64 6f 20 70 61 79 6c 6f 61 64 20 62 69 6e } //6 [*] Baixando payload bin
		$a_01_2 = {5b 2b 5d 20 50 72 6f 63 65 73 73 20 48 6f 6c 6c 6f 77 69 6e 67 20 63 6f 6e 63 6c 75 } //10 [+] Process Hollowing conclu
		$a_01_3 = {72 69 61 20 6e 6f 20 70 72 6f 63 65 73 73 6f 20 61 6c 76 6f 2e 2e 2e } //8 ria no processo alvo...
		$a_01_4 = {5b 2a 5d 20 50 61 79 6c 6f 61 64 20 62 61 69 78 61 64 6f 3a 20 25 7a 75 20 62 79 74 65 73 } //2 [*] Payload baixado: %zu bytes
	condition:
		((#a_01_0  & 1)*4+(#a_01_1  & 1)*6+(#a_01_2  & 1)*10+(#a_01_3  & 1)*8+(#a_01_4  & 1)*2) >=30
 
}