
rule Trojan_Win32_MyDoom_AMD_MTB{
	meta:
		description = "Trojan:Win32/MyDoom.AMD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 03 00 00 "
		
	strings :
		$a_01_0 = {0f b7 c0 6a 1a 99 59 f7 f9 80 c2 61 88 54 3d e4 47 3b fe } //3
		$a_03_1 = {56 8b 35 54 10 50 00 57 8d 45 bc 68 f0 30 50 00 50 ff d6 8d 45 bc 50 ff 15 ?? ?? ?? ?? 8b f8 85 ff } //2
		$a_01_2 = {8d 45 bc 68 d4 30 50 00 50 ff d6 8d 45 bc 50 57 ff 15 } //1
	condition:
		((#a_01_0  & 1)*3+(#a_03_1  & 1)*2+(#a_01_2  & 1)*1) >=6
 
}
rule Trojan_Win32_MyDoom_AMD_MTB_2{
	meta:
		description = "Trojan:Win32/MyDoom.AMD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0b 00 0b 00 0b 00 00 "
		
	strings :
		$a_01_0 = {4e 65 74 44 79 5f 4d 75 74 65 78 5f 50 73 79 63 68 6f } //1 NetDy_Mutex_Psycho
		$a_01_1 = {4e 65 74 44 79 3a 20 57 65 20 68 61 76 65 20 72 65 77 72 69 74 74 65 6e 20 4e 65 74 53 6b 79 } //1 NetDy: We have rewritten NetSky
		$a_01_2 = {4e 65 74 44 79 3a 20 54 68 61 74 73 20 61 20 67 6f 6f 64 20 74 61 63 74 69 63 20 74 6f 20 64 65 74 72 6f 79 20 74 68 65 20 62 61 67 6c 65 20 61 6e 64 20 6d 79 64 6f 6f 6d 20 77 6f 72 6d 73 } //1 NetDy: Thats a good tactic to detroy the bagle and mydoom worms
		$a_01_3 = {4e 65 74 44 79 3a 20 4f 75 72 20 67 72 6f 75 70 20 77 69 6c 6c 20 63 6f 6e 74 69 6e 75 65 20 74 68 65 20 77 61 72 } //1 NetDy: Our group will continue the war
		$a_01_4 = {4e 65 74 44 79 3a 20 4d 61 6c 77 61 72 65 20 77 72 69 74 65 72 73 20 27 45 6e 64 27 20 63 6f 6d 65 73 20 74 72 75 65 } //1 NetDy: Malware writers 'End' comes true
		$a_01_5 = {4e 65 74 44 79 3a 20 4f 75 72 20 53 6f 63 69 61 6c 20 45 6e 67 69 6e 65 65 72 69 6e 67 20 69 73 20 74 68 65 20 62 65 73 74 } //1 NetDy: Our Social Engineering is the best
		$a_01_6 = {4e 65 74 44 79 3a 20 57 65 20 61 72 65 20 67 72 65 65 74 69 6e 67 20 61 6c 6c 20 72 75 73 73 69 61 20 70 65 6f 70 6c 65 21 } //1 NetDy: We are greeting all russia people!
		$a_01_7 = {55 53 41 20 53 55 43 4b 53 21 21 21 20 41 46 47 48 41 4e 20 53 55 43 4b 53 20 32 21 21 21 20 42 55 52 4e 2c 20 53 41 44 44 41 4d 21 20 42 55 52 4e 20 49 4e 20 48 45 4c 4c 21 20 41 4e 44 20 59 4f 55 2c 20 4f 53 41 4d 41 20 42 49 4e 20 4c 41 44 45 4e 2c } //1 USA SUCKS!!! AFGHAN SUCKS 2!!! BURN, SADDAM! BURN IN HELL! AND YOU, OSAMA BIN LADEN,
		$a_01_8 = {42 55 52 4e 20 49 4e 20 54 48 45 20 44 45 56 49 4c 53 20 46 49 52 45 20 32 21 21 21 } //1 BURN IN THE DEVILS FIRE 2!!!
		$a_01_9 = {53 48 41 4d 45 20 4f 4e 20 59 4f 55 20 4d 52 2e 20 42 55 53 48 21 21 21 } //1 SHAME ON YOU MR. BUSH!!!
		$a_01_10 = {54 48 49 53 20 49 53 20 41 20 4d 45 53 53 41 47 45 20 46 52 4f 4d 3a 20 53 6b 79 6e 65 74 2e 63 7a 2d 46 41 4e 41 54 49 43 4f 4e } //1 THIS IS A MESSAGE FROM: Skynet.cz-FANATICON
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1+(#a_01_8  & 1)*1+(#a_01_9  & 1)*1+(#a_01_10  & 1)*1) >=11
 
}