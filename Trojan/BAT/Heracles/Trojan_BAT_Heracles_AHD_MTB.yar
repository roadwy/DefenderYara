
rule Trojan_BAT_Heracles_AHD_MTB{
	meta:
		description = "Trojan:BAT/Heracles.AHD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,32 00 32 00 02 00 00 "
		
	strings :
		$a_03_0 = {07 0c 20 a0 00 00 00 28 ?? ?? ?? ?? 3a 21 00 00 00 20 a1 00 00 00 28 ?? ?? ?? ?? 3a 12 00 00 00 } //30
		$a_81_1 = {47 4f 43 53 50 58 2d 2d 39 6f 64 69 6a 31 70 37 68 55 36 59 57 79 6e 51 64 56 35 48 38 35 47 4e 4d 42 73 } //20 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
	condition:
		((#a_03_0  & 1)*30+(#a_81_1  & 1)*20) >=50
 
}