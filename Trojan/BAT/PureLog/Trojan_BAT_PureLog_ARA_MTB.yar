
rule Trojan_BAT_PureLog_ARA_MTB{
	meta:
		description = "Trojan:BAT/PureLog.ARA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {08 09 58 0c 06 07 08 07 8e 69 08 59 6f ?? ?? ?? 0a 25 0d 16 30 ea } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}
rule Trojan_BAT_PureLog_ARA_MTB_2{
	meta:
		description = "Trojan:BAT/PureLog.ARA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 02 00 00 "
		
	strings :
		$a_01_0 = {57 44 20 4b 49 4c 4c 45 52 2e 67 2e 72 65 73 6f 75 72 63 65 73 } //2 WD KILLER.g.resources
		$a_01_1 = {24 35 35 39 31 34 35 33 39 2d 31 62 39 30 2d 34 64 37 34 2d 39 36 64 30 2d 66 66 31 63 38 34 31 35 39 31 66 64 } //2 $55914539-1b90-4d74-96d0-ff1c841591fd
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2) >=4
 
}
rule Trojan_BAT_PureLog_ARA_MTB_3{
	meta:
		description = "Trojan:BAT/PureLog.ARA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 02 00 00 "
		
	strings :
		$a_01_0 = {52 44 69 71 54 47 6d 41 51 44 54 4d 39 36 58 36 58 79 2e 71 30 61 73 4a 79 6c 6d 70 62 56 64 46 68 5a 46 4c 58 } //2 RDiqTGmAQDTM96X6Xy.q0asJylmpbVdFhZFLX
		$a_01_1 = {71 6b 63 69 64 42 76 35 55 78 63 41 47 46 32 35 53 44 2e 32 33 63 51 66 31 59 67 62 46 77 4a 69 72 75 50 45 4a } //2 qkcidBv5UxcAGF25SD.23cQf1YgbFwJiruPEJ
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2) >=4
 
}