
rule Backdoor_MacOS_Mokes_A{
	meta:
		description = "Backdoor:MacOS/Mokes.A,SIGNATURE_TYPE_MACHOHSTR_EXT,09 00 09 00 09 00 00 "
		
	strings :
		$a_00_0 = {61 76 66 6f 75 6e 64 61 74 69 6f 6e 63 61 6d 65 72 61 } //1 avfoundationcamera
		$a_00_1 = {52 49 46 46 00 73 63 72 65 65 6e 73 68 6f 74 73 2f } //1
		$a_00_2 = {2a 2e 64 6f 63 00 2a 2e 64 6f 63 78 00 2a 2e 78 6c 73 00 2a 2e 78 6c 73 78 00 51 41 75 64 69 6f } //1 ⸪潤c⸪潤硣⨀砮獬⨀砮獬x䅑摵潩
		$a_00_3 = {53 70 6f 74 6c 69 67 68 74 64 00 53 6b 79 70 65 00 73 6f 61 67 65 6e 74 00 44 72 6f 70 62 6f 78 } //1 灓瑯楬桧摴匀祫数猀慯敧瑮䐀潲扰硯
		$a_00_4 = {71 75 69 63 6b 6c 6f 6f 6b 64 00 47 6f 6f 67 6c 65 00 43 68 72 6f 6d 65 } //1 畱捩汫潯摫䜀潯汧e桃潲敭
		$a_00_5 = {46 69 72 65 66 6f 78 00 50 72 6f 66 69 6c 65 73 } //1 楆敲潦x牐景汩獥
		$a_00_6 = {74 72 75 73 74 64 00 6b 6b 74 00 2f 63 63 58 58 58 58 58 58 } //1 牴獵摴欀瑫⼀捣塘塘塘
		$a_00_7 = {70 00 6f 00 77 00 65 00 72 00 73 00 68 00 65 00 6c 00 6c 00 2e 00 65 00 78 00 65 00 } //1 powershell.exe
		$a_00_8 = {2f 00 6b 00 65 00 79 00 73 00 2f 00 62 00 6f 00 74 00 } //1 /keys/bot
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1+(#a_00_5  & 1)*1+(#a_00_6  & 1)*1+(#a_00_7  & 1)*1+(#a_00_8  & 1)*1) >=9
 
}