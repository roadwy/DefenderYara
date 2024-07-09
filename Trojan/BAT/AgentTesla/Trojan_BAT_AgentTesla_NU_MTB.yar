
rule Trojan_BAT_AgentTesla_NU_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.NU!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {20 00 01 00 00 0a 03 04 28 ?? ?? ?? 06 03 04 17 58 20 00 3a 00 00 5d 91 59 06 58 06 5d 0b 03 04 20 00 3a 00 00 5d 07 d2 9c 03 0c 2b 00 } //1
		$a_01_1 = {35 00 50 00 48 00 34 00 37 00 35 00 4e 00 47 00 42 00 38 00 59 00 45 00 46 00 39 00 34 00 34 00 5a 00 46 00 43 00 49 00 35 00 41 00 } //1 5PH475NGB8YEF944ZFCI5A
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}
rule Trojan_BAT_AgentTesla_NU_MTB_2{
	meta:
		description = "Trojan:BAT/AgentTesla.NU!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_02_0 = {07 02 09 18 6f [0-04] 1f ?? 28 [0-04] 28 [0-04] 6f [0-04] 26 09 18 d6 0d 09 08 31 } //1
		$a_02_1 = {91 08 61 07 11 ?? 91 61 b4 9c 11 [0-02] 6f [0-04] 17 da fe [0-09] 2c ?? 16 13 [0-02] 2b [0-02] 11 ?? 17 d6 13 [0-02] 11 ?? 17 d6 13 ?? 11 ?? 11 ?? 31 } //1
	condition:
		((#a_02_0  & 1)*1+(#a_02_1  & 1)*1) >=2
 
}
rule Trojan_BAT_AgentTesla_NU_MTB_3{
	meta:
		description = "Trojan:BAT/AgentTesla.NU!MTB,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 04 00 00 "
		
	strings :
		$a_03_0 = {07 06 08 11 04 6f ?? ?? ?? 0a 13 05 08 11 05 58 0c 11 04 11 05 59 13 04 11 04 16 3d ?? ?? ?? ff } //5
		$a_01_1 = {53 70 66 53 65 74 4b 65 79 } //1 SpfSetKey
		$a_01_2 = {53 00 70 00 6f 00 6f 00 66 00 65 00 72 00 2e 00 50 00 72 00 6f 00 70 00 65 00 72 00 74 00 69 00 65 00 73 00 2e 00 52 00 65 00 73 00 6f 00 75 00 72 00 63 00 65 00 73 00 } //1 Spoofer.Properties.Resources
		$a_01_3 = {48 77 69 64 45 64 69 74 49 74 65 6d } //1 HwidEditItem
	condition:
		((#a_03_0  & 1)*5+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=8
 
}