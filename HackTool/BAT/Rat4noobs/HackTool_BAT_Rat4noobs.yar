
rule HackTool_BAT_Rat4noobs{
	meta:
		description = "HackTool:BAT/Rat4noobs,SIGNATURE_TYPE_PEHSTR_EXT,0c 00 0c 00 09 00 00 "
		
	strings :
		$a_01_0 = {52 61 74 34 4e 6f 6f 62 73 } //10 Rat4Noobs
		$a_01_1 = {5f 4d 73 67 49 6e } //1 _MsgIn
		$a_01_2 = {5f 4b 69 6c 6c 50 72 6f 63 } //1 _KillProc
		$a_01_3 = {5f 56 69 73 69 74 4c 69 6e 6b } //1 _VisitLink
		$a_01_4 = {5f 50 65 72 73 69 73 74 61 6e 63 65 } //1 _Persistance
		$a_01_5 = {5f 52 65 67 69 73 74 72 79 42 6f 74 4b 69 6c 6c 65 72 } //1 _RegistryBotKiller
		$a_01_6 = {54 00 43 00 50 00 20 00 53 00 74 00 72 00 65 00 73 00 73 00 65 00 72 00 20 00 45 00 6e 00 61 00 62 00 6c 00 65 00 64 00 } //1 TCP Stresser Enabled
		$a_01_7 = {53 6c 6f 77 6c 6f 72 69 73 } //1 Slowloris
		$a_01_8 = {52 65 6d 6f 74 65 20 57 65 62 63 61 6d } //1 Remote Webcam
	condition:
		((#a_01_0  & 1)*10+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1+(#a_01_8  & 1)*1) >=12
 
}