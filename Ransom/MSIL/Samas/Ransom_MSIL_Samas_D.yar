
rule Ransom_MSIL_Samas_D{
	meta:
		description = "Ransom:MSIL/Samas.D,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 02 00 00 01 00 "
		
	strings :
		$a_01_0 = {11 04 11 05 9a 0c 08 20 80 00 00 00 28 59 00 00 0a 08 28 3e 00 00 0a 11 05 17 58 13 05 } //01 00 
		$a_01_1 = {00 09 53 00 41 00 4c 00 54 00 00 } //00 00 
		$a_00_2 = {78 28 } //01 00  x(
	condition:
		any of ($a_*)
 
}
rule Ransom_MSIL_Samas_D_2{
	meta:
		description = "Ransom:MSIL/Samas.D,SIGNATURE_TYPE_PEHSTR_EXT,10 00 10 00 08 00 00 02 00 "
		
	strings :
		$a_01_0 = {42 39 31 37 37 35 34 42 43 46 45 37 31 37 45 42 34 46 37 43 45 30 34 41 35 42 31 31 41 36 33 35 31 45 45 43 35 30 31 35 } //02 00  B917754BCFE717EB4F7CE04A5B11A6351EEC5015
		$a_01_1 = {6b 73 64 67 68 6b 73 64 67 68 6b 64 64 67 64 66 67 64 66 67 66 64 } //02 00  ksdghksdghkddgdfgdfgfd
		$a_01_2 = {71 77 65 72 74 79 68 67 66 67 66 64 64 66 68 67 66 64 66 64 67 66 64 67 64 67 64 } //02 00  qwertyhgfgfddfhgfdfdgfdgdgd
		$a_01_3 = {71 77 65 72 74 66 64 73 64 6b 6b 69 75 68 67 64 67 73 64 73 66 64 73 64 66 } //02 00  qwertfdsdkkiuhgdgsdsfdsdf
		$a_01_4 = {67 68 74 72 66 64 66 64 65 77 73 64 66 67 74 79 68 67 6a 67 67 68 66 64 67 } //02 00  ghtrfdfdewsdfgtyhgjgghfdg
		$a_01_5 = {6f 73 69 65 79 72 67 76 62 73 67 6e 68 6b 66 6c 6b 73 74 65 73 61 64 66 61 6b 64 68 61 6b 73 6a 66 67 79 6a 71 71 77 67 6a 72 77 67 65 68 6a 67 66 64 6a 67 64 66 66 67 } //02 00  osieyrgvbsgnhkflkstesadfakdhaksjfgyjqqwgjrwgehjgfdjgdffg
		$a_01_6 = {66 67 64 66 67 68 68 74 72 64 73 66 67 68 64 67 68 64 66 68 64 73 68 73 68 66 68 66 64 67 68 } //02 00  fgdfghhtrdsfghdghdfhdshshfhfdgh
		$a_01_7 = {68 64 66 67 6b 68 69 6f 69 75 67 79 66 79 67 68 64 73 65 65 72 74 64 66 79 67 75 } //00 00  hdfgkhioiugyfyghdseertdfygu
		$a_00_8 = {78 38 01 00 0f 00 0f 00 0c 00 } //00 01 
	condition:
		any of ($a_*)
 
}
rule Ransom_MSIL_Samas_D_3{
	meta:
		description = "Ransom:MSIL/Samas.D,SIGNATURE_TYPE_PEHSTR_EXT,0f 00 0f 00 0c 00 00 01 00 "
		
	strings :
		$a_01_0 = {73 64 67 61 73 66 73 65 } //01 00  sdgasfse
		$a_01_1 = {64 6f 6c 69 6f 68 64 79 6a 6b 61 6a 64 } //02 00  doliohdyjkajd
		$a_01_2 = {7a 64 73 72 66 76 64 67 32 33 2e 65 78 65 } //02 00  zdsrfvdg23.exe
		$a_01_3 = {72 6f 63 6b 32 2e 65 78 65 } //02 00  rock2.exe
		$a_01_4 = {65 67 7a 65 72 74 79 75 68 66 67 64 66 68 6a 73 2e 65 78 65 } //02 00  egzertyuhfgdfhjs.exe
		$a_01_5 = {65 78 74 75 72 79 64 74 63 66 64 67 2e 65 78 65 } //04 00  exturydtcfdg.exe
		$a_01_6 = {64 6c 6c 68 67 6a 64 76 64 66 67 64 66 } //04 00  dllhgjdvdfgdf
		$a_01_7 = {64 73 6a 68 66 63 67 66 6e 6a 73 67 68 66 75 79 74 61 77 65 79 61 6a 67 73 68 64 66 73 64 66 } //04 00  dsjhfcgfnjsghfuytaweyajgshdfsdf
		$a_01_8 = {73 6a 67 66 71 6a 77 67 66 73 64 66 6b 61 73 6a 62 6a 66 73 6a 6f 6b 68 6d 67 6e 68 74 67 72 66 64 } //04 00  sjgfqjwgfsdfkasjbjfsjokhmgnhtgrfd
		$a_01_9 = {6f 73 69 65 79 72 67 76 62 73 67 6e 68 6b 66 6c 6b 73 74 65 73 61 64 66 61 6b 64 68 61 6b 73 6a 66 67 79 6a 71 71 77 67 6a 72 77 67 65 68 6a 67 66 64 6a 67 64 66 66 67 } //08 00  osieyrgvbsgnhkflkstesadfakdhaksjfgyjqqwgjrwgehjgfdjgdffg
		$a_01_10 = {2a 00 2e 00 73 00 74 00 75 00 62 00 62 00 69 00 6e 00 } //08 00  *.stubbin
		$a_01_11 = {2a 00 2e 00 62 00 65 00 72 00 6b 00 73 00 68 00 69 00 72 00 65 00 } //00 00  *.berkshire
		$a_00_12 = {5d 04 00 00 7a 99 03 80 5c 3c 00 00 7b } //99 03 
	condition:
		any of ($a_*)
 
}