
rule Trojan_Win32_Amadey_ASGJ_MTB{
	meta:
		description = "Trojan:Win32/Amadey.ASGJ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {7a 61 64 61 66 65 72 6f 66 75 78 65 73 69 77 69 74 75 78 65 78 75 6c 61 74 61 20 76 75 76 6f 70 61 20 6a 69 67 61 6d 75 77 6f 6d 20 6c 6f 67 61 77 75 66 61 64 61 76 75 6a 6f 6b 65 20 6c 61 76 65 68 65 70 65 64 61 74 65 77 61 76 75 66 61 70 6f 6d 75 78 61 6d 65 } //1 zadaferofuxesiwituxexulata vuvopa jigamuwom logawufadavujoke lavehepedatewavufapomuxame
		$a_01_1 = {63 75 70 69 6b 6f 66 61 78 69 63 75 73 61 76 65 7a 65 74 69 7a } //1 cupikofaxicusavezetiz
		$a_01_2 = {53 00 69 00 63 00 65 00 72 00 65 00 6d 00 65 00 20 00 62 00 69 00 6e 00 61 00 6c 00 65 00 76 00 65 00 20 00 63 00 65 00 6b 00 61 00 72 00 69 00 68 00 65 00 7a 00 6f 00 79 00 6f 00 67 00 } //1 Sicereme binaleve cekarihezoyog
		$a_01_3 = {53 00 75 00 68 00 6f 00 68 00 75 00 66 00 6f 00 20 00 78 00 69 00 68 00 75 00 73 00 20 00 6a 00 6f 00 6c 00 65 00 77 00 6f 00 6c 00 6f 00 20 00 6e 00 69 00 63 00 6f 00 72 00 69 00 64 00 75 00 63 00 75 00 62 00 69 00 6c 00 6f 00 20 00 79 00 65 00 74 00 65 00 66 00 20 00 77 00 61 00 67 00 61 00 6e 00 6f 00 } //1 Suhohufo xihus jolewolo nicoriducubilo yetef wagano
		$a_01_4 = {6c 00 61 00 6b 00 6f 00 6d 00 65 00 66 00 6f 00 72 00 65 00 62 00 69 00 67 00 75 00 20 00 64 00 6f 00 77 00 65 00 67 00 61 00 79 00 69 00 20 00 68 00 6f 00 72 00 } //1 lakomeforebigu dowegayi hor
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}