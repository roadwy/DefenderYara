
rule Trojan_BAT_AMSIBypass_AHC_MTB{
	meta:
		description = "Trojan:BAT/AMSIBypass.AHC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,1e 00 1e 00 04 00 00 "
		
	strings :
		$a_01_0 = {41 70 70 6c 79 45 76 65 6e 74 54 72 61 63 69 6e 67 41 64 6a 75 73 74 6d 65 6e 74 73 } //5 ApplyEventTracingAdjustments
		$a_01_1 = {41 70 70 6c 79 53 65 63 75 72 69 74 79 41 64 6a 75 73 74 6d 65 6e 74 73 } //10 ApplySecurityAdjustments
		$a_81_2 = {53 6b 79 70 65 7b 41 38 34 38 33 43 30 31 2d 45 38 34 30 2d 34 41 38 44 2d 38 33 46 35 2d 39 41 43 30 43 33 38 38 30 33 39 30 62 62 2d 42 42 44 39 31 36 39 31 32 33 39 38 38 31 31 7d } //15 Skype{A8483C01-E840-4A8D-83F5-9AC0C3880390bb-BBD916912398811}
		$a_03_3 = {11 1a 91 fe 01 16 fe 01 13 1b 11 1b 2c 0b 72 ?? ?? ?? 70 73 ?? ?? ?? 0a 7a 00 11 1a 17 58 13 1a 11 1a 11 0f 8e 69 fe 04 13 1c 11 1c 2d c1 } //30
	condition:
		((#a_01_0  & 1)*5+(#a_01_1  & 1)*10+(#a_81_2  & 1)*15+(#a_03_3  & 1)*30) >=30
 
}