
rule Backdoor_BAT_LimeRat_GA_MTB{
	meta:
		description = "Backdoor:BAT/LimeRat.GA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 0c 00 00 "
		
	strings :
		$a_80_0 = {5b 44 41 45 5d } //[DAE]  1
		$a_80_1 = {5b 55 52 4c 5d } //[URL]  1
		$a_80_2 = {5b 4e 41 4d 45 5d } //[NAME]  1
		$a_80_3 = {5b 46 49 4c 45 4c 4f 43 41 5d } //[FILELOCA]  1
		$a_80_4 = {5b 54 73 6b 6d 67 72 5d } //[Tskmgr]  1
		$a_80_5 = {5b 57 69 6e 64 44 65 66 5d } //[WindDef]  1
		$a_80_6 = {5b 52 65 67 69 73 74 72 79 5d } //[Registry]  1
		$a_80_7 = {44 69 73 61 62 6c 65 52 65 67 69 73 74 72 79 54 6f 6f 6c 73 } //DisableRegistryTools  1
		$a_80_8 = {44 69 73 61 62 6c 65 54 61 73 6b 4d 67 72 } //DisableTaskMgr  1
		$a_80_9 = {44 69 73 61 62 6c 65 41 6e 74 69 53 70 79 77 61 72 65 } //DisableAntiSpyware  1
		$a_80_10 = {50 72 6f 63 65 73 73 4e 61 6d 65 } //ProcessName  1
		$a_80_11 = {6e 75 72 5c 6e 6f 69 73 72 65 76 74 6e 65 72 72 75 63 5c 73 77 6f 64 6e 69 77 5c 74 66 6f 73 6f 72 63 69 6d 5c 65 72 61 77 74 66 6f 73 } //nur\noisrevtnerruc\swodniw\tfosorcim\erawtfos  1
	condition:
		((#a_80_0  & 1)*1+(#a_80_1  & 1)*1+(#a_80_2  & 1)*1+(#a_80_3  & 1)*1+(#a_80_4  & 1)*1+(#a_80_5  & 1)*1+(#a_80_6  & 1)*1+(#a_80_7  & 1)*1+(#a_80_8  & 1)*1+(#a_80_9  & 1)*1+(#a_80_10  & 1)*1+(#a_80_11  & 1)*1) >=10
 
}