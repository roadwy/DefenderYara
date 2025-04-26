
rule Trojan_BAT_AgentTesla_RTB_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.RTB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,21 00 21 00 12 00 00 "
		
	strings :
		$a_80_0 = {2f 63 20 70 69 6e 67 20 79 61 68 6f 6f 2e 63 6f 6d } ///c ping yahoo.com  10
		$a_80_1 = {44 65 62 75 67 67 69 6e 67 4d 6f 64 65 73 } //DebuggingModes  10
		$a_80_2 = {47 65 74 41 73 73 65 6d 62 6c 69 65 73 } //GetAssemblies  10
		$a_80_3 = {74 72 61 6e 73 66 65 72 2e 73 68 } //transfer.sh  1
		$a_80_4 = {59 6b 67 62 67 6b 64 66 70 67 61 75 72 77 66 67 61 74 } //Ykgbgkdfpgaurwfgat  1
		$a_80_5 = {51 68 70 61 70 2e 50 72 6f 70 65 72 74 69 65 73 2e 52 65 73 6f 75 72 63 65 73 } //Qhpap.Properties.Resources  1
		$a_80_6 = {30 6d 63 2d 67 6c 6f 62 61 6c 2e 63 6f 6d } //0mc-global.com  1
		$a_80_7 = {59 65 6c 66 69 76 69 6b 6c 6a 78 73 78 67 78 68 78 } //Yelfivikljxsxgxhx  1
		$a_80_8 = {56 77 66 64 78 64 6e 2e 50 72 6f 70 65 72 74 69 65 73 2e 52 65 73 6f 75 72 63 65 73 } //Vwfdxdn.Properties.Resources  1
		$a_80_9 = {63 64 6e 2e 64 69 73 63 6f 72 64 61 70 70 2e 63 6f 6d } //cdn.discordapp.com  1
		$a_80_10 = {55 73 77 61 74 72 66 78 74 75 76 77 62 76 71 77 } //Uswatrfxtuvwbvqw  1
		$a_80_11 = {4a 6a 78 70 61 2e 50 72 6f 70 65 72 74 69 65 73 2e 52 65 73 6f 75 72 63 65 73 } //Jjxpa.Properties.Resources  1
		$a_80_12 = {54 76 77 72 61 67 6d 72 6b 75 62 71 77 } //Tvwragmrkubqw  1
		$a_80_13 = {51 70 63 68 6b 2e 50 72 6f 70 65 72 74 69 65 73 2e 52 65 73 6f 75 72 63 65 73 } //Qpchk.Properties.Resources  1
		$a_80_14 = {46 6f 6d 79 6b 63 7a 78 6f 65 7a 75 76 6a 70 77 } //Fomykczxoezuvjpw  1
		$a_80_15 = {42 68 61 69 6c 68 2e 50 72 6f 70 65 72 74 69 65 73 2e 52 65 73 6f 75 72 63 65 73 } //Bhailh.Properties.Resources  1
		$a_80_16 = {49 65 73 69 79 69 6e 6e 65 77 6e } //Iesiyinnewn  1
		$a_80_17 = {46 67 65 77 70 68 2e 50 72 6f 70 65 72 74 69 65 73 2e 52 65 73 6f 75 72 63 65 73 } //Fgewph.Properties.Resources  1
	condition:
		((#a_80_0  & 1)*10+(#a_80_1  & 1)*10+(#a_80_2  & 1)*10+(#a_80_3  & 1)*1+(#a_80_4  & 1)*1+(#a_80_5  & 1)*1+(#a_80_6  & 1)*1+(#a_80_7  & 1)*1+(#a_80_8  & 1)*1+(#a_80_9  & 1)*1+(#a_80_10  & 1)*1+(#a_80_11  & 1)*1+(#a_80_12  & 1)*1+(#a_80_13  & 1)*1+(#a_80_14  & 1)*1+(#a_80_15  & 1)*1+(#a_80_16  & 1)*1+(#a_80_17  & 1)*1) >=33
 
}