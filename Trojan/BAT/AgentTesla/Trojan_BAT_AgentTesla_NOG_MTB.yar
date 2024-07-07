
rule Trojan_BAT_AgentTesla_NOG_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.NOG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0b 00 0b 00 03 00 00 "
		
	strings :
		$a_03_0 = {0a 0b 06 16 73 90 01 03 0a 73 90 01 03 0a 0c 08 07 6f 90 01 03 0a 07 6f 90 01 03 0a 0d de 1e 90 00 } //10
		$a_80_1 = {78 4e 59 4c 45 71 36 4c 6f 54 6a 44 71 37 49 66 6b 34 63 2e 47 57 35 64 53 77 36 48 35 52 54 4a 39 71 70 4d 46 4c 6e } //xNYLEq6LoTjDq7Ifk4c.GW5dSw6H5RTJ9qpMFLn  1
		$a_80_2 = {45 38 79 58 30 63 66 41 66 5a 63 49 4f 42 62 71 32 30 54 2e 66 48 49 74 6f 51 66 6f 63 31 78 53 79 6b 67 79 47 4f 6b } //E8yX0cfAfZcIOBbq20T.fHItoQfoc1xSykgyGOk  1
	condition:
		((#a_03_0  & 1)*10+(#a_80_1  & 1)*1+(#a_80_2  & 1)*1) >=11
 
}