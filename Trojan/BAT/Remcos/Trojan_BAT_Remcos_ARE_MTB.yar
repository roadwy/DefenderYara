
rule Trojan_BAT_Remcos_ARE_MTB{
	meta:
		description = "Trojan:BAT/Remcos.ARE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {0a 2b f1 0b 2b f8 02 50 06 91 17 2d 18 26 02 50 06 02 50 07 91 9c 02 50 07 08 9c 06 17 58 0a 07 17 59 0b 2b 03 0c 2b e6 06 07 32 da } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}
rule Trojan_BAT_Remcos_ARE_MTB_2{
	meta:
		description = "Trojan:BAT/Remcos.ARE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {0d 16 13 08 2b 13 00 07 08 11 08 09 28 ?? 00 00 06 00 00 11 08 17 58 13 08 11 08 07 6f ?? 00 00 0a 2f 0b 08 6f ?? 00 00 0a 09 fe 04 2b 01 16 13 09 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}
rule Trojan_BAT_Remcos_ARE_MTB_3{
	meta:
		description = "Trojan:BAT/Remcos.ARE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {0c 2b 33 02 0d 16 13 04 09 12 04 28 ?? 00 00 0a 07 06 08 18 6f ?? 00 00 0a 1f 10 28 ?? 00 00 0a 6f ?? 00 00 0a de 0b 11 04 2c 06 09 28 ?? 00 00 0a dc 08 18 58 0c 08 06 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}
rule Trojan_BAT_Remcos_ARE_MTB_4{
	meta:
		description = "Trojan:BAT/Remcos.ARE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 "
		
	strings :
		$a_01_0 = {16 0b 2b 12 00 06 07 17 07 1f 1f 5f 62 1f 64 5a 9e 00 07 17 58 0b 07 06 8e 69 fe 04 0c 08 2d e4 } //2
		$a_03_1 = {16 0c 2b 18 00 06 19 28 ?? 00 00 06 0a 04 07 08 91 6f ?? 01 00 0a 00 00 08 17 58 0c 08 03 fe 04 0d 09 2d e0 } //1
	condition:
		((#a_01_0  & 1)*2+(#a_03_1  & 1)*1) >=3
 
}
rule Trojan_BAT_Remcos_ARE_MTB_5{
	meta:
		description = "Trojan:BAT/Remcos.ARE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {06 26 7e 03 00 00 04 18 6f 42 00 00 0a 00 02 02 02 03 03 03 04 03 04 0e 04 28 08 00 00 06 0a 2b 00 } //1
		$a_01_1 = {7e 04 00 00 04 28 3e 00 00 0a 02 6f 3f 00 00 0a 6f 40 00 00 0a 0a 7e 03 00 00 04 06 25 0b 6f 41 00 00 0a 00 07 0c 2b 00 08 2a } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}
rule Trojan_BAT_Remcos_ARE_MTB_6{
	meta:
		description = "Trojan:BAT/Remcos.ARE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {07 11 06 11 07 6f ?? 00 00 0a 13 08 09 12 08 28 ?? 00 00 0a 6f ?? 00 00 0a 00 09 12 08 28 ?? 00 00 0a 6f ?? 00 00 0a 00 09 12 08 28 ?? 00 00 0a 6f ?? 00 00 0a 00 20 00 1e 01 00 13 09 08 6f ?? 00 00 0a 09 6f ?? 00 00 0a d6 11 09 fe 02 16 fe 01 13 0a 11 0a 2c 0c 00 08 09 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}
rule Trojan_BAT_Remcos_ARE_MTB_7{
	meta:
		description = "Trojan:BAT/Remcos.ARE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 "
		
	strings :
		$a_03_0 = {0d 16 13 04 2b 1f 08 11 04 07 11 04 91 09 11 04 09 6f ?? 00 00 0a 5d 6f ?? 00 00 0a 61 d2 9c 11 04 17 58 13 04 11 04 07 8e 69 32 da 06 08 6f ?? 00 00 0a 06 16 6f } //2
		$a_01_1 = {50 00 61 00 67 00 61 00 6d 00 65 00 6e 00 74 00 6f 00 2e 00 4e 00 6f 00 76 00 6f 00 62 00 61 00 6e 00 63 00 6f 00 2e 00 70 00 64 00 66 00 } //1 Pagamento.Novobanco.pdf
	condition:
		((#a_03_0  & 1)*2+(#a_01_1  & 1)*1) >=3
 
}
rule Trojan_BAT_Remcos_ARE_MTB_8{
	meta:
		description = "Trojan:BAT/Remcos.ARE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 04 00 00 "
		
	strings :
		$a_03_0 = {0a 0a 06 72 91 01 00 70 6f ?? 00 00 0a 26 06 6f ?? 00 00 0a 26 02 73 a7 00 00 0a 7d 16 00 00 04 02 73 a8 00 00 0a 7d 17 00 00 04 } //2
		$a_03_1 = {16 0b 2b 0e 00 1f 19 28 ?? 00 00 0a 00 00 07 17 58 0b 07 20 96 00 00 00 fe 04 0c 08 2d e6 } //1
		$a_01_2 = {33 64 62 32 33 63 34 35 2d 31 34 63 63 2d 34 35 62 65 2d 39 63 35 38 2d 37 30 63 36 37 33 38 62 35 39 62 37 } //1 3db23c45-14cc-45be-9c58-70c6738b59b7
		$a_01_3 = {46 69 6c 65 52 65 6e 61 6d 65 72 5c 6f 62 6a 5c 44 65 62 75 67 5c 46 49 63 6f 2e 70 64 62 } //1 FileRenamer\obj\Debug\FIco.pdb
	condition:
		((#a_03_0  & 1)*2+(#a_03_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=5
 
}
rule Trojan_BAT_Remcos_ARE_MTB_9{
	meta:
		description = "Trojan:BAT/Remcos.ARE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 09 00 00 "
		
	strings :
		$a_03_0 = {0a 16 0a 2b 0e 20 e8 03 00 00 28 ?? 00 00 0a 06 17 58 0a 06 1b 32 ee } //2
		$a_01_1 = {6d 64 6e 63 6b 68 7a 6e 74 6d 76 6b 34 73 62 6e 65 77 71 63 66 37 74 35 79 70 61 32 37 35 36 37 } //1 mdnckhzntmvk4sbnewqcf7t5ypa27567
		$a_01_2 = {61 65 6d 37 38 75 34 6a 79 33 68 70 70 77 6b 61 71 77 6a 6a 32 6a 67 6d 75 7a 6d 61 72 34 64 38 } //1 aem78u4jy3hppwkaqwjj2jgmuzmar4d8
		$a_01_3 = {63 63 76 6b 33 79 63 66 62 7a 32 70 74 6d 62 6a 6e 6b 7a 70 65 78 72 34 73 35 62 6a 66 6e 6d 62 } //1 ccvk3ycfbz2ptmbjnkzpexr4s5bjfnmb
		$a_01_4 = {74 6d 66 34 77 39 64 71 39 78 79 66 62 6c 73 70 38 66 75 33 79 74 77 68 38 7a 78 38 61 76 61 64 } //1 tmf4w9dq9xyfblsp8fu3ytwh8zx8avad
		$a_01_5 = {37 39 65 39 33 65 6b 36 6a 72 77 6e 71 71 77 79 79 70 67 65 66 74 34 71 73 6b 65 72 7a 6a 77 66 } //1 79e93ek6jrwnqqwyypgeft4qskerzjwf
		$a_01_6 = {72 63 72 66 35 6b 39 68 79 66 71 72 61 71 33 34 66 36 61 62 33 66 78 6e 35 65 37 79 35 72 6d 70 } //1 rcrf5k9hyfqraq34f6ab3fxn5e7y5rmp
		$a_01_7 = {66 37 36 33 64 71 6e 39 67 61 71 63 79 68 37 6b 37 78 76 71 37 38 6a 77 64 65 78 38 73 61 63 73 } //1 f763dqn9gaqcyh7k7xvq78jwdex8sacs
		$a_01_8 = {36 37 30 30 61 35 36 64 2d 63 30 61 63 2d 34 63 32 61 2d 62 66 61 64 2d 33 33 35 33 31 38 31 34 38 31 65 35 } //1 6700a56d-c0ac-4c2a-bfad-3353181481e5
	condition:
		((#a_03_0  & 1)*2+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1+(#a_01_8  & 1)*1) >=10
 
}