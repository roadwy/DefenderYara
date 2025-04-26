
rule Trojan_Win64_Zusy_AZY_MTB{
	meta:
		description = "Trojan:Win64/Zusy.AZY!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 03 00 00 "
		
	strings :
		$a_03_0 = {44 8b c0 48 8d 95 ?? ?? ?? ?? 48 8d 4d 80 e8 ?? ?? ?? ?? 4c 8d 4c 24 78 41 b8 00 08 00 00 48 8d 95 ?? ?? ?? ?? 48 8b cb ff 15 } //3
		$a_01_1 = {4c 89 74 24 28 c7 44 24 20 00 00 00 80 45 33 c9 45 33 c0 48 8b d0 48 8b ce ff 15 } //1
		$a_01_2 = {6c 6f 67 6e 61 74 69 6f 6e 70 72 69 6d 65 63 61 72 72 61 72 6f 2e 63 6f 6d 2f 73 65 74 74 69 6e 67 73 2f 63 6f 6e 66 69 67 32 2e 7a 69 70 } //2 lognationprimecarraro.com/settings/config2.zip
	condition:
		((#a_03_0  & 1)*3+(#a_01_1  & 1)*1+(#a_01_2  & 1)*2) >=6
 
}
rule Trojan_Win64_Zusy_AZY_MTB_2{
	meta:
		description = "Trojan:Win64/Zusy.AZY!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 03 00 00 "
		
	strings :
		$a_01_0 = {44 8b 15 71 0b 77 00 65 4c 8b 1c 25 58 00 00 00 4f 8b 1c d3 41 ba 30 00 00 00 4d 03 d3 4c 8b 1c 24 4c 89 51 10 48 89 69 08 4c 89 19 4c 8d 5c 24 08 c7 41 18 00 80 00 00 4c 89 59 20 49 89 4a 40 } //1
		$a_01_1 = {8b 05 cf 00 77 00 65 48 8b 1c 25 58 00 00 00 48 8b 1c c3 b8 30 00 00 00 48 03 c3 48 89 84 24 c0 00 00 00 f0 83 60 38 ef 48 8b 42 18 48 8b 18 48 8b 42 20 48 8b 28 48 8b 42 28 48 8b 30 48 8b 42 30 48 8b 38 48 8b 42 58 4c 8b 20 48 8b 42 60 4c 8b 28 48 8b 42 68 4c 8b 30 48 8b 42 70 4c 8b 38 } //3
		$a_01_2 = {69 6e 66 69 6e 69 74 79 63 68 65 61 74 73 5c 47 61 6d 65 48 65 6c 70 65 72 73 4c 6f 61 64 65 72 5f 5f 4e 45 57 5c 62 69 6e 5c 52 65 6c 65 61 73 65 5c 6e 65 74 38 2e 30 5c 77 69 6e 2d 78 36 34 5c 6e 61 74 69 76 65 5c 47 61 6d 65 48 65 6c 70 65 72 73 4c 6f 61 64 65 72 5f 5f 4e 45 57 2e 70 64 62 } //2 infinitycheats\GameHelpersLoader__NEW\bin\Release\net8.0\win-x64\native\GameHelpersLoader__NEW.pdb
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*3+(#a_01_2  & 1)*2) >=6
 
}