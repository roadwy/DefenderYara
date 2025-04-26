
rule Trojan_Win32_StealC_NG_MTB{
	meta:
		description = "Trojan:Win32/StealC.NG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0b 00 0b 00 0a 00 00 "
		
	strings :
		$a_81_0 = {74 6f 63 75 72 6f 62 61 74 65 6b 69 78 61 74 65 6b 65 79 61 6a 61 73 6f 72 69 6c 75 70 75 72 } //2 tocurobatekixatekeyajasorilupur
		$a_81_1 = {57 65 76 20 73 6f 63 61 6a 75 67 6f 73 69 64 61 74 61 79 69 20 7a 6f 6c 6f 74 69 78 69 6c 65 6d 61 63 75 72 65 66 75 76 75 } //1 Wev socajugosidatayi zolotixilemacurefuvu
		$a_81_2 = {6a 69 63 61 7a 75 67 61 79 6f 72 65 79 69 76 75 77 61 68 65 76 61 67 69 6d 75 73 75 20 76 75 73 75 67 75 6c 61 72 75 } //1 jicazugayoreyivuwahevagimusu vusugularu
		$a_81_3 = {79 75 62 75 6b 61 6b 69 74 69 77 6f 63 6f 66 61 6d 65 6e 69 74 75 62 61 79 75 63 6f 7a 20 72 65 77 61 63 69 6e 69 66 6f 74 61 63 65 7a } //1 yubukakitiwocofamenitubayucoz rewacinifotacez
		$a_81_4 = {6c 69 7a 69 74 65 73 65 72 61 79 } //1 liziteseray
		$a_81_5 = {78 6f 68 65 6a 6f 63 75 6d 6f 73 69 6e 75 6e 6f 73 69 68 69 77 69 6d 6f 6d 65 6a 65 62 75 7a 20 6a 61 66 61 62 75 6c 61 64 } //1 xohejocumosinunosihiwimomejebuz jafabulad
		$a_81_6 = {73 6f 76 6f 6b 6f 73 75 74 75 78 61 6e 65 72 69 73 65 77 75 67 61 6a 75 7a 69 6e 75 64 75 } //1 sovokosutuxanerisewugajuzinudu
		$a_81_7 = {74 65 78 6f 73 69 6d 75 73 69 } //1 texosimusi
		$a_81_8 = {77 6f 62 75 7a 61 6e 65 74 75 64 75 67 65 72 75 } //1 wobuzanetudugeru
		$a_81_9 = {6d 73 69 6d 67 33 32 2e 64 6c 6c } //1 msimg32.dll
	condition:
		((#a_81_0  & 1)*2+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1+(#a_81_5  & 1)*1+(#a_81_6  & 1)*1+(#a_81_7  & 1)*1+(#a_81_8  & 1)*1+(#a_81_9  & 1)*1) >=11
 
}