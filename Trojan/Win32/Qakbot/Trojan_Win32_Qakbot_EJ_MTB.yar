
rule Trojan_Win32_Qakbot_EJ_MTB{
	meta:
		description = "Trojan:Win32/Qakbot.EJ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0f 00 0f 00 0b 00 00 "
		
	strings :
		$a_01_0 = {44 6c 6c 52 65 67 69 73 74 65 72 53 65 72 76 65 72 } //10 DllRegisterServer
		$a_01_1 = {62 67 6f 56 69 52 70 76 2e 64 6c 6c } //1 bgoViRpv.dll
		$a_01_2 = {46 4c 67 47 64 6a 5a 71 50 } //1 FLgGdjZqP
		$a_01_3 = {4e 73 6b 52 58 33 74 62 6a } //1 NskRX3tbj
		$a_01_4 = {57 49 46 33 50 4c 6e 72 70 } //1 WIF3PLnrp
		$a_01_5 = {6b 67 71 55 58 6e 75 44 66 } //1 kgqUXnuDf
		$a_01_6 = {69 56 6b 62 6b 58 57 69 2e 64 6c 6c } //1 iVkbkXWi.dll
		$a_01_7 = {4e 57 71 4d 4d 41 38 66 64 } //1 NWqMMA8fd
		$a_01_8 = {6b 63 32 4b 37 43 52 72 } //1 kc2K7CRr
		$a_01_9 = {77 67 4a 4b 46 61 4f } //1 wgJKFaO
		$a_01_10 = {79 65 42 70 35 77 31 69 58 71 } //1 yeBp5w1iXq
	condition:
		((#a_01_0  & 1)*10+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1+(#a_01_8  & 1)*1+(#a_01_9  & 1)*1+(#a_01_10  & 1)*1) >=15
 
}