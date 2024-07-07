
rule Trojan_Win32_Zupd_A{
	meta:
		description = "Trojan:Win32/Zupd.A,SIGNATURE_TYPE_PEHSTR,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {66 59 81 c2 f1 00 00 00 83 c2 07 51 8b 72 14 03 f0 8b 7a 0c 03 fb 8b 4a 10 f3 a4 83 c2 28 59 66 49 75 e8 } //1
		$a_01_1 = {43 3a 5c 57 49 4e 44 4f 57 53 5c 73 79 73 74 65 6d 33 32 5c 61 70 70 65 6e 64 2e 65 78 65 00 65 61 79 73 72 68 72 00 6b 65 72 6e 65 6c 33 32 00 } //1 㩃坜义佄南獜獹整㍭尲灡数摮攮數攀祡牳牨欀牥敮㍬2
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}