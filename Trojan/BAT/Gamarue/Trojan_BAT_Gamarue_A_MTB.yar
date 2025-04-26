
rule Trojan_BAT_Gamarue_A_MTB{
	meta:
		description = "Trojan:BAT/Gamarue.A!MTB,SIGNATURE_TYPE_PEHSTR_EXT,20 00 20 00 07 00 00 "
		
	strings :
		$a_80_0 = {69 74 74 65 72 5f 73 42 4f 39 5a 68 6a 6f 48 42 36 5a 55 33 65 71 5a 50 4b 5a 77 6c 66 59 71 74 56 6f 44 42 4b 6d 35 4c 58 58 6b 47 46 63 57 72 30 4c 72 65 78 39 32 43 36 6c 69 50 6d 4a 64 75 51 46 62 77 53 43 44 6f 6f 7a 46 51 4d 4a 6b 72 34 4e 50 6a 4a 74 4f 4e 41 44 6b 6a 5a 6d 52 6a 44 51 69 73 72 50 66 67 71 49 4a 37 52 79 45 77 41 63 4b 38 74 4e 45 61 6c 65 39 51 36 6d 63 } //itter_sBO9ZhjoHB6ZU3eqZPKZwlfYqtVoDBKm5LXXkGFcWr0Lrex92C6liPmJduQFbwSCDoozFQMJkr4NPjJtONADkjZmRjDQisrPfgqIJ7RyEwAcK8tNEale9Q6mc  5
		$a_80_1 = {70 7a 64 68 44 4f 78 52 49 66 72 63 68 70 6d 42 5a 53 42 42 33 69 73 6e 45 61 41 } //pzdhDOxRIfrchpmBZSBB3isnEaA  5
		$a_80_2 = {37 75 43 66 46 76 41 46 65 6a 75 42 75 30 75 79 42 73 73 75 47 47 41 79 31 4d 58 63 43 59 79 58 7a 74 4d 47 75 45 38 77 51 34 74 76 61 4c 41 39 72 30 68 4e 4f 54 48 38 38 } //7uCfFvAFejuBu0uyBssuGGAy1MXcCYyXztMGuE8wQ4tvaLA9r0hNOTH88  5
		$a_80_3 = {4d 68 4a 35 51 73 5a 6a 54 63 51 7a 51 59 68 59 57 58 41 4e 37 4c 41 6b 79 73 } //MhJ5QsZjTcQzQYhYWXAN7LAkys  5
		$a_80_4 = {41 70 70 44 61 74 61 69 74 74 65 72 } //AppDataitter  4
		$a_80_5 = {55 52 4c 69 74 74 65 72 5f 46 49 4c 45 } //URLitter_FILE  4
		$a_80_6 = {6a 6c 79 42 6d 33 48 32 79 6b 35 55 61 6e 58 4f 36 35 65 38 6e 53 56 59 65 63 70 36 30 74 34 62 5a 62 63 4f 69 63 30 41 48 49 41 3d 3d 69 74 74 65 72 } //jlyBm3H2yk5UanXO65e8nSVYecp60t4bZbcOic0AHIA==itter  4
	condition:
		((#a_80_0  & 1)*5+(#a_80_1  & 1)*5+(#a_80_2  & 1)*5+(#a_80_3  & 1)*5+(#a_80_4  & 1)*4+(#a_80_5  & 1)*4+(#a_80_6  & 1)*4) >=32
 
}