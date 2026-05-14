
rule Trojan_Win32_Dridex_LM_MTB{
	meta:
		description = "Trojan:Win32/Dridex.LM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,1e 00 1e 00 02 00 00 "
		
	strings :
		$a_01_0 = {8a 54 34 58 0f b6 84 34 58 01 00 00 03 c7 0f b6 ca 03 c8 0f b6 f9 8a 44 3c 58 88 44 34 58 46 88 54 3c 58 81 fe 00 01 00 00 } //20
		$a_01_1 = {88 4c 24 13 74 17 0f b6 44 24 12 0f b6 4c 1c 58 03 c8 0f b6 c1 8a 4c 24 13 32 4c 04 58 88 0e 46 43 83 ef 01 } //10
	condition:
		((#a_01_0  & 1)*20+(#a_01_1  & 1)*10) >=30
 
}