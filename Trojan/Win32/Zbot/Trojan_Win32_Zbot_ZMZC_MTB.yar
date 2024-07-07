
rule Trojan_Win32_Zbot_ZMZC_MTB{
	meta:
		description = "Trojan:Win32/Zbot.ZMZC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,19 00 19 00 07 00 00 "
		
	strings :
		$a_01_0 = {8b 06 8a e9 32 c5 fe c1 } //10
		$a_01_1 = {8b 50 0c 03 f2 03 fe 2b c0 2b d2 0b d0 ac c1 e2 07 d0 e8 72 f6 } //10
		$a_80_2 = {4c 50 54 6c 46 6e 6d 6e 2e 65 78 65 } //LPTlFnmn.exe  1
		$a_80_3 = {38 62 73 4f 30 37 41 61 2e 65 78 65 } //8bsO07Aa.exe  1
		$a_80_4 = {4b 46 43 58 69 37 64 65 2e 65 78 65 } //KFCXi7de.exe  1
		$a_80_5 = {57 6d 35 5f 6f 66 4a 55 2e 65 78 65 } //Wm5_ofJU.exe  1
		$a_80_6 = {50 4f 46 6e 4b 4a 52 6a 2e 65 78 65 } //POFnKJRj.exe  1
	condition:
		((#a_01_0  & 1)*10+(#a_01_1  & 1)*10+(#a_80_2  & 1)*1+(#a_80_3  & 1)*1+(#a_80_4  & 1)*1+(#a_80_5  & 1)*1+(#a_80_6  & 1)*1) >=25
 
}