
rule Trojan_BAT_AgentTesla_VV_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.VV!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 06 00 00 "
		
	strings :
		$a_80_0 = {33 37 2e 30 2e 31 31 2e 31 36 34 } //37.0.11.164  1
		$a_80_1 = {52 65 6e 65 76 63 74 5f 4b 6d 65 68 72 66 6d 65 2e 70 6e 67 } //Renevct_Kmehrfme.png  1
		$a_01_2 = {44 6f 77 6e 6c 6f 61 64 44 61 74 61 } //1 DownloadData
		$a_01_3 = {67 65 74 5f 42 75 66 66 } //1 get_Buff
		$a_01_4 = {49 6e 76 6f 6b 65 4d 65 6d 62 65 72 } //1 InvokeMember
		$a_01_5 = {54 6f 41 72 72 61 79 } //1 ToArray
	condition:
		((#a_80_0  & 1)*1+(#a_80_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=6
 
}