
rule Trojan_Win64_Meterpreter_AHF_MTB{
	meta:
		description = "Trojan:Win64/Meterpreter.AHF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,14 00 14 00 02 00 00 "
		
	strings :
		$a_03_0 = {01 d0 89 85 ?? ?? 00 00 0f b7 85 ?? ?? 00 00 89 c1 8b 85 ?? ?? 00 00 89 c2 0f b6 c1 f6 f2 0f b6 c4 88 85 ?? ?? 00 00 } //20
		$a_03_1 = {66 f7 f1 66 89 85 ?? ?? 00 00 8b 85 ?? ?? 00 00 89 c2 0f b6 85 ?? ?? 00 00 31 d0 88 85 ?? ?? 00 00 } //20
	condition:
		((#a_03_0  & 1)*20+(#a_03_1  & 1)*20) >=20
 
}