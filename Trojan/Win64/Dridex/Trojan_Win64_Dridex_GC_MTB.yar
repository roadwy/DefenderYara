
rule Trojan_Win64_Dridex_GC_MTB{
	meta:
		description = "Trojan:Win64/Dridex.GC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0c 00 0c 00 03 00 00 "
		
	strings :
		$a_02_0 = {44 8a 0a 48 81 c1 ?? ?? ?? ?? 44 8a 54 24 ?? 41 80 e2 ?? 44 88 54 24 ?? 89 44 24 2c 48 8b 54 24 ?? 46 8a 14 02 45 28 ca 8b 44 24 ?? 05 ?? ?? ?? ?? 44 8b 5c 24 ?? 4c 8b 44 24 ?? 48 8b 74 24 ?? 46 88 14 06 48 89 4c 24 ?? 41 39 c3 0f 84 } //10
		$a_80_1 = {61 69 6e 63 6c 75 64 69 6e 67 31 70 } //aincluding1p  1
		$a_80_2 = {72 61 69 73 69 6e 67 6e 35 38 37 } //raisingn587  1
	condition:
		((#a_02_0  & 1)*10+(#a_80_1  & 1)*1+(#a_80_2  & 1)*1) >=12
 
}
rule Trojan_Win64_Dridex_GC_MTB_2{
	meta:
		description = "Trojan:Win64/Dridex.GC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 07 00 00 "
		
	strings :
		$a_80_0 = {43 34 63 72 61 73 68 74 6f 4b 54 50 61 67 65 67 6f 64 7a 69 6c 6c 61 73 6c } //C4crashtoKTPagegodzillasl  1
		$a_80_1 = {54 72 65 6c 65 61 73 65 64 4c 65 61 6b 65 64 66 43 68 72 6f 6d 65 } //TreleasedLeakedfChrome  1
		$a_80_2 = {74 6f 42 44 65 62 69 61 6e 73 61 6e 64 62 6f 78 69 6e 67 41 64 61 6e 64 7a 48 35 } //toBDebiansandboxingAdandzH5  1
		$a_80_3 = {4b 69 6e 63 6c 75 64 69 6e 67 77 65 62 73 69 74 65 73 59 73 6f 6e 34 69 77 } //KincludingwebsitesYson4iw  1
		$a_80_4 = {72 65 66 72 65 73 68 63 61 6e 63 65 6c 73 74 61 74 65 64 74 72 75 73 74 6e 6f 31 68 65 57 68 69 6c 65 61 6e 64 } //refreshcancelstatedtrustno1heWhileand  1
		$a_80_5 = {57 62 53 79 61 6e 6b 65 65 34 6e 6f 74 74 68 6f 6d 61 73 69 6e } //WbSyankee4notthomasin  1
		$a_80_6 = {4d 75 70 64 61 74 65 73 2e 39 32 74 68 65 74 68 65 64 61 78 7a 74 68 65 6f 70 65 6e 65 64 } //Mupdates.92thethedaxztheopened  1
	condition:
		((#a_80_0  & 1)*1+(#a_80_1  & 1)*1+(#a_80_2  & 1)*1+(#a_80_3  & 1)*1+(#a_80_4  & 1)*1+(#a_80_5  & 1)*1+(#a_80_6  & 1)*1) >=6
 
}