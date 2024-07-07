
rule Backdoor_BAT_Zegost_GG_MTB{
	meta:
		description = "Backdoor:BAT/Zegost.GG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,1c 00 1c 00 0c 00 00 "
		
	strings :
		$a_80_0 = {73 76 70 37 2e } //svp7.  10
		$a_80_1 = {25 73 5c 61 64 6d 69 6e 24 5c 68 61 63 6b 73 68 65 6e 2e 65 78 65 } //%s\admin$\hackshen.exe  10
		$a_80_2 = {56 4d 77 61 72 65 } //VMware  1
		$a_80_3 = {5b 43 4c 45 41 52 5d } //[CLEAR]  1
		$a_80_4 = {5b 50 72 69 6e 74 20 53 63 72 65 65 6e 5d } //[Print Screen]  1
		$a_80_5 = {61 6e 67 65 6c } //angel  1
		$a_80_6 = {78 70 75 73 65 72 } //xpuser  1
		$a_80_7 = {4d 63 41 66 65 65 } //McAfee  1
		$a_80_8 = {42 69 74 44 65 66 65 6e 64 65 72 } //BitDefender  1
		$a_80_9 = {70 61 73 73 77 6f 72 64 } //password  1
		$a_80_10 = {5c 5c 2e 5c 50 48 59 53 49 43 41 4c 44 52 49 56 45 30 } //\\.\PHYSICALDRIVE0  1
		$a_80_11 = {53 65 44 65 62 75 67 50 72 69 76 69 6c 65 67 65 } //SeDebugPrivilege  1
	condition:
		((#a_80_0  & 1)*10+(#a_80_1  & 1)*10+(#a_80_2  & 1)*1+(#a_80_3  & 1)*1+(#a_80_4  & 1)*1+(#a_80_5  & 1)*1+(#a_80_6  & 1)*1+(#a_80_7  & 1)*1+(#a_80_8  & 1)*1+(#a_80_9  & 1)*1+(#a_80_10  & 1)*1+(#a_80_11  & 1)*1) >=28
 
}