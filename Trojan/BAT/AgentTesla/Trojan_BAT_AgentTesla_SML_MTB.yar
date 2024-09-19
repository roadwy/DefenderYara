
rule Trojan_BAT_AgentTesla_SML_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.SML!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_00_0 = {07 11 09 91 11 06 61 11 08 59 20 00 02 00 00 58 20 00 01 00 00 5d 20 00 04 00 00 58 20 00 02 00 00 5d 13 0a 16 13 10 2b 14 11 0a 11 10 5a 1d 58 20 00 01 00 00 5d 26 11 10 17 58 13 10 11 10 19 32 e7 } //1
		$a_81_1 = {47 35 5a 50 45 46 38 36 35 48 43 38 38 47 30 47 43 44 34 47 44 30 } //1 G5ZPEF865HC88G0GCD4GD0
	condition:
		((#a_00_0  & 1)*1+(#a_81_1  & 1)*1) >=2
 
}
rule Trojan_BAT_AgentTesla_SML_MTB_2{
	meta:
		description = "Trojan:BAT/AgentTesla.SML!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 03 00 00 "
		
	strings :
		$a_81_0 = {48 46 34 34 50 37 38 52 5a 34 38 4a 55 59 49 42 47 47 35 34 50 34 } //1 HF44P78RZ48JUYIBGG54P4
		$a_81_1 = {08 5d 13 11 07 11 11 91 13 12 11 12 11 09 61 13 13 11 13 20 00 04 00 00 58 13 14 11 14 20 00 04 00 00 59 13 15 11 15 11 0f 59 } //1
		$a_81_2 = {19 08 5d 13 1a 07 11 1a 91 13 1b 11 1b 11 12 61 13 1c 11 1c 20 00 04 00 00 58 13 1d 11 1d 20 00 04 00 00 59 13 1e 11 1e 11 18 59 13 1f 11 1f 20 00 02 00 00 } //1
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1) >=2
 
}
rule Trojan_BAT_AgentTesla_SML_MTB_3{
	meta:
		description = "Trojan:BAT/AgentTesla.SML!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_81_0 = {35 41 58 42 4a 5a 37 38 48 38 35 37 59 35 34 44 37 37 58 4a 50 38 } //1 5AXBJZ78H857Y54D77XJP8
		$a_81_1 = {43 68 65 63 6b 42 6f 78 53 74 75 64 69 6f 2e 57 69 6e 46 6f 72 6d 73 2e 50 72 6f 70 65 72 74 69 65 73 2e 52 65 73 6f 75 72 63 65 73 2e 72 65 73 6f 75 72 63 65 73 } //1 CheckBoxStudio.WinForms.Properties.Resources.resources
		$a_81_2 = {00 02 09 11 06 28 21 00 00 06 13 07 02 11 06 08 28 22 00 00 06 13 08 02 07 11 08 08 28 23 00 00 06 13 09 02 07 11 06 08 11 07 11 09 28 24 00 00 06 } //1
		$a_81_3 = {24 63 62 30 63 38 64 35 34 2d 31 34 64 31 2d 34 66 35 35 2d 62 36 35 35 2d 64 38 34 36 65 37 35 37 66 65 32 66 } //1 $cb0c8d54-14d1-4f55-b655-d846e757fe2f
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1) >=4
 
}