
rule Trojan_BAT_AMSIBypass_AHB_MTB{
	meta:
		description = "Trojan:BAT/AMSIBypass.AHB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,5a 00 5a 00 03 00 00 "
		
	strings :
		$a_03_0 = {07 08 06 08 9a 28 ?? ?? ?? 0a 03 5b d2 9c 08 17 58 0c 08 07 8e 69 32 e8 } //40
		$a_01_1 = {41 70 70 6c 79 45 76 65 6e 74 54 72 61 63 69 6e 67 41 64 6a 75 73 74 6d 65 6e 74 73 } //30 ApplyEventTracingAdjustments
		$a_01_2 = {41 70 70 6c 79 53 65 63 75 72 69 74 79 41 64 6a 75 73 74 6d 65 6e 74 73 } //20 ApplySecurityAdjustments
	condition:
		((#a_03_0  & 1)*40+(#a_01_1  & 1)*30+(#a_01_2  & 1)*20) >=90
 
}