
rule Trojan_Win32_Dridex_C_MTB{
	meta:
		description = "Trojan:Win32/Dridex.C!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {29 c6 8b 44 24 20 8a 3c 30 88 3c 10 88 1c 30 c7 44 24 3c [0-04] c7 44 24 38 [0-04] 8b 4c 24 08 8a 1c 08 66 8b 44 24 1e 66 0f af c0 0f b6 d3 66 89 44 24 36 01 fa 81 e2 [0-04] 8b 7c 24 20 8a 1c 17 8b 54 24 28 8b 0c 24 32 1c 0a 8b 4c 24 24 8b 14 24 88 1c 11 83 c2 01 8b 4c 24 2c 39 ca } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}