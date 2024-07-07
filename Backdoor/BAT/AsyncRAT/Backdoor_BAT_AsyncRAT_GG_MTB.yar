
rule Backdoor_BAT_AsyncRAT_GG_MTB{
	meta:
		description = "Backdoor:BAT/AsyncRAT.GG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,09 00 09 00 09 00 00 "
		
	strings :
		$a_80_0 = {53 65 6c 65 63 74 20 2a 20 66 72 6f 6d 20 41 6e 74 69 76 69 72 75 73 50 72 6f 64 75 63 74 } //Select * from AntivirusProduct  1
		$a_80_1 = {50 61 73 74 65 62 69 6e } //Pastebin  1
		$a_80_2 = {56 49 52 54 55 41 4c } //VIRTUAL  1
		$a_80_3 = {76 6d 77 61 72 65 } //vmware  1
		$a_80_4 = {53 62 69 65 44 6c 6c 2e 64 6c 6c } //SbieDll.dll  1
		$a_80_5 = {5c 6e 75 52 5c 6e 6f 69 73 72 65 56 74 6e 65 72 72 75 43 5c 73 77 6f 64 6e 69 57 5c 74 66 6f 73 6f 72 63 69 4d 5c 65 72 61 77 74 66 6f 53 } //\nuR\noisreVtnerruC\swodniW\tfosorciM\erawtfoS  1
		$a_80_6 = {50 6c 75 67 69 6e 2e 50 6c 75 67 69 6e } //Plugin.Plugin  1
		$a_80_7 = {73 63 68 74 61 73 6b 73 } //schtasks  1
		$a_80_8 = {50 61 63 6b 65 74 } //Packet  1
	condition:
		((#a_80_0  & 1)*1+(#a_80_1  & 1)*1+(#a_80_2  & 1)*1+(#a_80_3  & 1)*1+(#a_80_4  & 1)*1+(#a_80_5  & 1)*1+(#a_80_6  & 1)*1+(#a_80_7  & 1)*1+(#a_80_8  & 1)*1) >=9
 
}
rule Backdoor_BAT_AsyncRAT_GG_MTB_2{
	meta:
		description = "Backdoor:BAT/AsyncRAT.GG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 0a 00 00 "
		
	strings :
		$a_80_0 = {53 65 6c 65 63 74 20 2a 20 66 72 6f 6d 20 41 6e 74 69 76 69 72 75 73 50 72 6f 64 75 63 74 } //Select * from AntivirusProduct  1
		$a_80_1 = {6e 75 52 5c 6e 6f 69 73 72 65 56 74 6e 65 72 72 75 43 5c 73 77 6f 64 6e 69 57 5c 74 66 6f 73 6f 72 63 69 4d 5c 65 72 61 77 74 66 6f 53 } //nuR\noisreVtnerruC\swodniW\tfosorciM\erawtfoS  1
		$a_80_2 = {50 6c 75 67 69 6e 2e 50 6c 75 67 69 6e } //Plugin.Plugin  1
		$a_80_3 = {50 61 63 5f 6b 65 74 } //Pac_ket  1
		$a_80_4 = {4c 6f 67 5f 67 65 72 73 } //Log_gers  1
		$a_80_5 = {44 69 73 61 62 6c 65 52 65 61 6c 74 69 6d 65 4d 6f 6e 69 74 6f 72 69 6e 67 } //DisableRealtimeMonitoring  1
		$a_80_6 = {44 69 73 61 62 6c 65 42 65 68 61 76 69 6f 72 4d 6f 6e 69 74 6f 72 69 6e 67 } //DisableBehaviorMonitoring  1
		$a_80_7 = {6c 6c 69 6b 6b 73 61 74 } //llikksat  1
		$a_80_8 = {72 65 6b 63 61 48 73 73 65 63 6f 72 50 } //rekcaHssecorP  1
		$a_80_9 = {73 6b 73 61 74 68 63 73 } //sksathcs  1
	condition:
		((#a_80_0  & 1)*1+(#a_80_1  & 1)*1+(#a_80_2  & 1)*1+(#a_80_3  & 1)*1+(#a_80_4  & 1)*1+(#a_80_5  & 1)*1+(#a_80_6  & 1)*1+(#a_80_7  & 1)*1+(#a_80_8  & 1)*1+(#a_80_9  & 1)*1) >=7
 
}