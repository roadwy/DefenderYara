
rule Trojan_BAT_AgentTesla_JTB_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.JTB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_03_0 = {02 06 02 8e 69 6a 5d d4 02 06 02 8e 69 6a 5d d4 91 03 06 03 8e 69 6a 5d d4 91 61 28 90 01 03 0a 02 06 17 6a 58 02 8e 69 6a 5d d4 91 28 90 01 03 0a 59 20 90 01 03 00 90 00 } //1
		$a_01_1 = {24 31 36 39 38 33 36 66 33 2d 35 32 35 65 2d 34 30 31 39 2d 39 64 38 30 2d 32 37 32 65 65 62 36 66 64 31 34 61 } //1 $169836f3-525e-4019-9d80-272eeb6fd14a
		$a_81_2 = {44 65 62 75 67 67 65 72 4e 6f 6e 55 73 65 72 43 6f 64 65 41 74 74 72 69 62 75 74 65 } //1 DebuggerNonUserCodeAttribute
		$a_81_3 = {47 65 74 42 79 74 65 73 } //1 GetBytes
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1) >=4
 
}