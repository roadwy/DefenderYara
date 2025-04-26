
rule Trojan_Win32_IcedID_BC_MSR{
	meta:
		description = "Trojan:Win32/IcedID.BC!MSR,SIGNATURE_TYPE_PEHSTR_EXT,14 00 14 00 0a 00 00 "
		
	strings :
		$a_01_0 = {45 6b 6e 5a 4d 52 4b 78 } //2 EknZMRKx
		$a_01_1 = {46 52 61 6d 62 6f 61 } //2 FRamboa
		$a_01_2 = {4b 4d 70 68 74 54 4c 4a } //2 KMphtTLJ
		$a_01_3 = {4d 70 4f 51 42 68 } //2 MpOQBh
		$a_01_4 = {52 6a 53 62 71 61 } //2 RjSbqa
		$a_01_5 = {62 4e 73 59 61 52 78 } //2 bNsYaRx
		$a_01_6 = {63 68 50 58 52 4d 77 4e 61 } //2 chPXRMwNa
		$a_01_7 = {67 54 53 71 64 56 67 62 57 53 4b } //2 gTSqdVgbWSK
		$a_01_8 = {6c 6b 69 65 41 55 57 41 7a } //2 lkieAUWAz
		$a_01_9 = {78 76 49 4c 6e 4a 4d 72 } //2 xvILnJMr
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2+(#a_01_2  & 1)*2+(#a_01_3  & 1)*2+(#a_01_4  & 1)*2+(#a_01_5  & 1)*2+(#a_01_6  & 1)*2+(#a_01_7  & 1)*2+(#a_01_8  & 1)*2+(#a_01_9  & 1)*2) >=20
 
}