
rule Backdoor_BAT_Bladabindi_BJ{
	meta:
		description = "Backdoor:BAT/Bladabindi.BJ,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_00_0 = {73 00 63 00 68 00 74 00 61 00 73 00 6b 00 73 00 20 00 2f 00 63 00 72 00 65 00 61 00 74 00 65 00 20 00 2f 00 73 00 63 00 20 00 6d 00 69 00 6e 00 75 00 74 00 65 00 20 00 2f 00 6d 00 6f 00 20 00 31 00 20 00 2f 00 74 00 6e 00 20 00 69 00 67 00 66 00 78 00 54 00 72 00 61 00 79 00 73 00 20 00 2f 00 74 00 72 00 } //2 schtasks /create /sc minute /mo 1 /tn igfxTrays /tr
		$a_03_1 = {1f 1d 0f 00 1a 28 90 01 01 00 00 06 90 00 } //1
		$a_03_2 = {1f 1d 0f 01 1a 28 90 01 01 00 00 06 90 00 } //1
	condition:
		((#a_00_0  & 1)*2+(#a_03_1  & 1)*1+(#a_03_2  & 1)*1) >=3
 
}