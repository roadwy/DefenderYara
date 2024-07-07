
rule TrojanDropper_Win32_Banker_E{
	meta:
		description = "TrojanDropper:Win32/Banker.E,SIGNATURE_TYPE_PEHSTR,01 00 01 00 03 00 00 "
		
	strings :
		$a_01_0 = {68 40 23 40 74 40 74 23 70 3a 40 2f 2f 76 69 40 73 75 40 23 61 6c 69 23 7a 61 63 61 40 6f 2e 62 23 40 6c 6f 40 67 2e 62 23 40 72 2f } //1 h@#@t@t#p:@//vi@su@#ali#zaca@o.b#@lo@g.b#@r/
		$a_01_1 = {23 72 40 23 65 40 40 67 20 61 64 64 20 22 48 40 23 4b 45 59 5f 43 40 55 52 52 45 40 4e 54 5f 55 53 45 52 5c 53 40 4f 46 23 40 54 57 40 41 52 45 5c 4d 69 63 72 40 6f 23 73 6f 66 74 5c 57 69 40 6e 23 40 64 6f 40 77 73 5c 43 75 72 40 72 65 40 23 6e 74 56 65 72 73 69 40 6f 6e 40 5c 52 23 40 75 23 6e 22 20 2f 23 76 20 73 40 23 79 40 40 23 40 73 23 40 79 40 20 2f 64 20 22 23 40 43 40 23 3a 5c } //1 #r@#e@@g add "H@#KEY_C@URRE@NT_USER\S@OF#@TW@ARE\Micr@o#soft\Wi@n#@do@ws\Cur@re@#ntVersi@on@\R#@u#n" /#v s@#y@@#@s#@y@ /d "#@C@#:\
		$a_01_2 = {23 40 43 40 23 3a 5c 40 73 79 23 73 40 40 23 74 65 61 40 23 6d 5c } //1 #@C@#:\@sy#s@@#tea@#m\
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=1
 
}