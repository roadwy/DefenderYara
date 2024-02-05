
rule Ransom_MSIL_Lockerrip_A{
	meta:
		description = "Ransom:MSIL/Lockerrip.A,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 07 00 00 01 00 "
		
	strings :
		$a_80_0 = {4b 69 6c 6c 65 72 4c 6f 63 6b 65 72 2e 65 78 65 00 } //KillerLocker.exe  01 00 
		$a_80_1 = {65 6e 63 72 79 70 74 20 2e 72 69 70 } //encrypt .rip  01 00 
		$a_80_2 = {73 75 61 20 63 68 61 76 65 20 73 65 72 61 6f 20 65 6c 69 6d 69 6e 61 64 61 73 20 65 6d 20 34 38 20 68 6f 72 61 73 2e } //sua chave serao eliminadas em 48 horas.  01 00 
		$a_80_3 = {5c 4b 69 6c 6c 65 72 4c 6f 63 6b 65 72 5c 4b 69 6c 6c 65 72 4c 6f 63 6b 65 72 5c 6f 62 6a 5c 52 65 6c 65 61 73 65 5c 4b 69 6c 6c 65 72 4c 6f 63 6b 65 72 2e 70 64 62 00 } //\KillerLocker\KillerLocker\obj\Release\KillerLocker.pdb  01 00 
		$a_80_4 = {24 38 33 39 65 39 33 38 65 2d 64 31 34 38 2d 34 31 35 39 2d 39 39 36 33 2d 31 36 35 33 30 35 63 64 65 65 36 31 00 } //$839e938e-d148-4159-9963-165305cdee61  01 00 
		$a_80_5 = {62 6e 74 44 65 63 72 79 70 74 65 72 } //bntDecrypter  01 00 
		$a_80_6 = {63 72 69 70 74 6f 67 72 61 66 69 61 20 41 45 53 20 32 35 36 20 42 49 54 20 4d 75 69 74 6f 20 66 6f 72 74 65 2e 52 65 61 6c 69 7a 65 20 6f 20 70 61 67 61 6d 65 6e 74 6f 20 65 6d 3a } //criptografia AES 256 BIT Muito forte.Realize o pagamento em:  00 00 
		$a_00_7 = {5d 04 00 00 } //d5 91 
	condition:
		any of ($a_*)
 
}