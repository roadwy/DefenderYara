
rule Trojan_BAT_AgentTesla_DLQ_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.DLQ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 08 00 00 "
		
	strings :
		$a_01_0 = {2d 00 54 00 2d 00 6f 00 2d 00 57 00 2d 00 69 00 2d 00 6e 00 2d 00 33 00 2d 00 32 00 2d 00 } //1 -T-o-W-i-n-3-2-
		$a_01_1 = {44 65 62 75 67 67 69 6e 67 4d 6f 64 65 73 } //1 DebuggingModes
		$a_01_2 = {00 47 65 74 54 79 70 65 00 } //1
		$a_01_3 = {00 47 65 74 50 69 78 65 6c 00 } //1 䜀瑥楐數l
		$a_01_4 = {00 43 6f 6c 6f 72 54 72 61 6e 73 6c 61 74 6f 72 00 } //1
		$a_01_5 = {50 00 55 00 2e 00 6f 00 6f 00 } //1 PU.oo
		$a_01_6 = {44 65 62 75 67 67 61 62 6c 65 41 74 74 72 69 62 75 74 65 } //1 DebuggableAttribute
		$a_01_7 = {00 54 6f 49 6e 74 33 32 00 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1) >=8
 
}
rule Trojan_BAT_AgentTesla_DLQ_MTB_2{
	meta:
		description = "Trojan:BAT/AgentTesla.DLQ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,09 00 09 00 09 00 00 "
		
	strings :
		$a_01_0 = {24 34 43 30 38 36 32 39 39 2d 38 43 31 31 2d 34 46 45 31 2d 39 34 46 45 2d 36 34 37 46 33 36 34 46 46 31 35 35 } //1 $4C086299-8C11-4FE1-94FE-647F364FF155
		$a_01_1 = {00 59 59 59 59 59 59 59 59 59 59 59 59 59 59 59 59 59 59 59 59 59 59 59 59 59 59 59 59 59 59 59 59 00 } //1 夀奙奙奙奙奙奙奙奙奙奙奙奙奙奙奙Y
		$a_01_2 = {55 38 33 34 32 35 32 33 35 33 34 } //1 U8342523534
		$a_01_3 = {49 00 6e 00 76 00 6f 00 6b 00 65 00 } //1 Invoke
		$a_01_4 = {00 47 65 74 54 79 70 65 00 } //1
		$a_01_5 = {00 54 6f 42 6f 6f 6c 65 61 6e 00 } //1
		$a_01_6 = {00 54 6f 49 6e 74 33 32 00 } //1
		$a_01_7 = {00 52 65 70 6c 61 63 65 00 54 6f 42 79 74 65 00 } //1 刀灥慬散吀䉯瑹e
		$a_01_8 = {00 43 6f 6d 70 61 72 65 53 74 72 69 6e 67 00 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1+(#a_01_8  & 1)*1) >=9
 
}