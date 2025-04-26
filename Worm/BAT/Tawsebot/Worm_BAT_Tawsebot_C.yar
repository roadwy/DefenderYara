
rule Worm_BAT_Tawsebot_C{
	meta:
		description = "Worm:BAT/Tawsebot.C,SIGNATURE_TYPE_PEHSTR_EXT,0b 00 0b 00 04 00 00 "
		
	strings :
		$a_01_0 = {41 6e 74 69 53 61 6e 64 62 6f 78 69 65 } //4 AntiSandboxie
		$a_01_1 = {46 61 6b 65 45 72 72 6f 72 4d 65 73 73 61 67 65 } //3 FakeErrorMessage
		$a_01_2 = {67 00 6f 00 74 00 6f 00 20 00 52 00 65 00 70 00 65 00 61 00 74 00 } //2 goto Repeat
		$a_01_3 = {53 74 65 61 6c 65 72 4c 6f 67 } //2 StealerLog
	condition:
		((#a_01_0  & 1)*4+(#a_01_1  & 1)*3+(#a_01_2  & 1)*2+(#a_01_3  & 1)*2) >=11
 
}