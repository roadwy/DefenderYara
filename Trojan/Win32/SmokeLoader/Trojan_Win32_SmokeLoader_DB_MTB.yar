
rule Trojan_Win32_SmokeLoader_DB_MTB{
	meta:
		description = "Trojan:Win32/SmokeLoader.DB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {8b 45 ec 8b 55 e8 01 10 8b 45 d8 03 45 ac 03 45 e8 8b 55 ec 31 02 6a 00 e8 ?? ?? ?? ?? 6a 00 e8 ?? ?? ?? ?? 6a 00 e8 ?? ?? ?? ?? 6a 00 e8 ?? ?? ?? ?? 6a 00 e8 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}
rule Trojan_Win32_SmokeLoader_DB_MTB_2{
	meta:
		description = "Trojan:Win32/SmokeLoader.DB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0c 00 0c 00 0a 00 00 "
		
	strings :
		$a_01_0 = {63 65 63 69 76 69 72 6f 67 75 73 75 76 61 6d 69 67 75 6b 65 6a 6f 79 65 6e } //2 cecivirogusuvamigukejoyen
		$a_01_1 = {6c 6f 77 69 77 75 64 6f 79 65 6b 61 67 69 79 69 6b 75 72 75 77 75 20 78 69 73 69 67 61 68 75 67 6f 70 61 6c 6f 6b 69 67 20 6b 75 73 61 68 69 } //2 lowiwudoyekagiyikuruwu xisigahugopalokig kusahi
		$a_01_2 = {70 69 73 6f 6a 75 70 65 73 75 68 65 7a 75 70 65 68 65 73 6f 74 6f 63 75 6e 6f 6d 65 67 75 7a 69 } //2 pisojupesuhezupehesotocunomeguzi
		$a_01_3 = {63 75 6c 61 6b 6f 63 69 6a 6f 74 75 74 75 78 69 6e 69 70 6f 6e 61 6e 20 72 61 66 20 6a 61 7a 61 6b 6f 64 75 62 } //2 culakocijotutuxiniponan raf jazakodub
		$a_01_4 = {73 65 70 75 6b 65 66 75 6d 65 6e 69 66 65 73 61 6c 65 72 69 62 65 68 61 6a 61 74 20 70 69 73 6f 6a 75 70 65 73 75 68 65 7a 75 70 65 68 65 73 6f 74 6f 63 75 6e 6f 6d 65 67 75 7a 69 20 6b 65 76 61 74 61 70 6f 62 61 78 61 68 69 76 69 6a 69 } //2 sepukefumenifesaleribehajat pisojupesuhezupehesotocunomeguzi kevatapobaxahiviji
		$a_01_5 = {54 69 74 65 6c 61 6e 75 66 75 20 6d 61 66 61 73 65 72 65 62 65 72 69 79 75 76 20 72 69 79 61 6a 65 78 75 20 6c 65 64 75 62 75 72 61 62 20 66 61 6c 65 79 61 74 6f 73 65 72 } //1 Titelanufu mafasereberiyuv riyajexu leduburab faleyatoser
		$a_01_6 = {43 3a 5c 79 6f 62 75 79 6f 74 69 63 65 7a 69 5c 6d 75 76 2e 70 64 62 } //1 C:\yobuyoticezi\muv.pdb
		$a_01_7 = {62 65 67 6f 78 69 72 61 6e 69 77 6f 64 75 68 69 62 61 6b 69 73 61 73 61 76 20 73 75 6c 75 76 6f 79 75 66 20 68 75 6a 61 67 6f 68 75 64 6f 70 69 6c 6f 70 61 73 6f 6d 20 74 75 79 75 78 61 74 69 68 61 72 6f 76 61 6b 69 7a 69 72 69 7a 75 76 69 68 65 64 6f 6d 20 68 75 77 69 7a 65 64 75 70 75 73 61 6b 69 66 61 79 69 66 61 70 61 67 61 62 65 79 } //1 begoxiraniwoduhibakisasav suluvoyuf hujagohudopilopasom tuyuxatiharovakizirizuvihedom huwizedupusakifayifapagabey
		$a_01_8 = {70 61 63 6f 6c 65 74 75 70 69 66 6f 64 6f 66 20 77 6f 74 6f 64 75 64 6f 6b 65 6a 61 78 65 7a 75 63 75 64 69 20 74 61 7a 65 78 } //1 pacoletupifodof wotodudokejaxezucudi tazex
		$a_01_9 = {47 75 68 69 6c 69 74 75 79 61 67 6f 72 75 6c 20 70 61 6a 69 62 75 7a 69 66 20 6e 65 6e 65 20 76 6f 67 6f 72 65 66 69 74 75 79 6f 74 } //1 Guhilituyagorul pajibuzif nene vogorefituyot
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2+(#a_01_2  & 1)*2+(#a_01_3  & 1)*2+(#a_01_4  & 1)*2+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1+(#a_01_8  & 1)*1+(#a_01_9  & 1)*1) >=12
 
}