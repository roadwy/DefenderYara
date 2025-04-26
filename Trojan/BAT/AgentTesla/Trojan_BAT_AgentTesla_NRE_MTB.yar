
rule Trojan_BAT_AgentTesla_NRE_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.NRE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,09 00 09 00 05 00 00 "
		
	strings :
		$a_01_0 = {11 07 17 58 13 07 11 07 11 06 8e 69 fe 04 13 08 11 } //5
		$a_01_1 = {58 69 64 65 72 } //1 Xider
		$a_01_2 = {55 6c 74 72 61 76 69 6f 6c 65 74 } //1 Ultraviolet
		$a_01_3 = {52 65 63 6f 6c 61 72 } //1 Recolar
		$a_01_4 = {43 00 79 00 62 00 65 00 72 00 58 00 69 00 64 00 65 00 } //1 CyberXide
	condition:
		((#a_01_0  & 1)*5+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=9
 
}
rule Trojan_BAT_AgentTesla_NRE_MTB_2{
	meta:
		description = "Trojan:BAT/AgentTesla.NRE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 07 00 00 "
		
	strings :
		$a_01_0 = {24 36 38 30 30 39 33 35 37 2d 41 41 46 45 2d 34 46 35 44 2d 38 34 31 37 2d 43 46 39 32 35 34 31 35 45 30 44 32 } //1 $68009357-AAFE-4F5D-8417-CF925415E0D2
		$a_01_1 = {61 52 33 6e 62 66 38 64 51 70 32 66 65 4c 6d 6b 33 31 2e 6c 53 66 67 41 70 61 74 6b 64 78 73 56 63 47 63 72 6b 74 6f 46 64 2e 72 65 73 6f 75 72 63 65 73 } //1 aR3nbf8dQp2feLmk31.lSfgApatkdxsVcGcrktoFd.resources
		$a_01_2 = {42 65 61 74 65 6d 73 2e 50 72 6f 70 65 72 74 69 65 73 2e 52 65 73 6f 75 72 63 65 73 2e 72 65 73 6f 75 72 63 65 73 } //1 Beatems.Properties.Resources.resources
		$a_01_3 = {43 6c 75 62 20 57 68 6f 6c 65 73 61 6c 65 } //1 Club Wholesale
		$a_01_4 = {44 65 62 75 67 67 61 62 6c 65 41 74 74 72 69 62 75 74 65 } //1 DebuggableAttribute
		$a_01_5 = {44 65 62 75 67 67 65 72 4e 6f 6e 55 73 65 72 43 6f 64 65 41 74 74 72 69 62 75 74 65 } //1 DebuggerNonUserCodeAttribute
		$a_01_6 = {47 65 74 54 79 70 65 73 } //1 GetTypes
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1) >=7
 
}