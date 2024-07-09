
rule Trojan_BAT_AgentTesla_ABZ_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.ABZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,10 00 10 00 04 00 00 "
		
	strings :
		$a_03_0 = {25 16 03 a2 6f [0-09] 0b 07 6f [0-04] 1f 09 9a 0c 08 72 [0-09] 14 14 19 8d ?? ?? ?? ?? 25 16 7e ?? ?? ?? ?? a2 25 17 7e ?? ?? ?? ?? a2 25 18 72 ?? ?? ?? ?? a2 6f ?? ?? ?? ?? 26 } //10
		$a_80_1 = {46 72 6f 6d 42 61 73 65 36 34 53 74 72 69 6e 67 } //FromBase64String  2
		$a_80_2 = {53 74 72 52 65 76 65 72 73 65 } //StrReverse  2
		$a_80_3 = {57 53 54 52 42 75 66 66 65 72 4d 61 72 73 68 61 6c 65 72 } //WSTRBufferMarshaler  2
	condition:
		((#a_03_0  & 1)*10+(#a_80_1  & 1)*2+(#a_80_2  & 1)*2+(#a_80_3  & 1)*2) >=16
 
}
rule Trojan_BAT_AgentTesla_ABZ_MTB_2{
	meta:
		description = "Trojan:BAT/AgentTesla.ABZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 03 00 00 "
		
	strings :
		$a_03_0 = {26 20 02 00 00 00 38 [0-04] 11 00 11 02 11 00 28 [0-03] 06 1e 5b 6f [0-03] 0a 6f [0-03] 0a 20 06 00 00 00 38 [0-04] 11 08 11 05 20 e8 03 00 00 73 [0-03] 0a 13 02 38 [0-04] 11 09 } //2
		$a_01_1 = {38 00 30 00 2e 00 36 00 36 00 2e 00 37 00 35 00 2e 00 32 00 37 00 2f 00 61 00 72 00 78 00 31 00 2d 00 4e 00 63 00 70 00 76 00 66 00 75 00 69 00 6a 00 6a 00 2e 00 62 00 6d 00 70 00 } //1 80.66.75.27/arx1-Ncpvfuijj.bmp
		$a_01_2 = {4c 00 74 00 71 00 6a 00 78 00 63 00 71 00 75 00 } //1 Ltqjxcqu
	condition:
		((#a_03_0  & 1)*2+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=4
 
}