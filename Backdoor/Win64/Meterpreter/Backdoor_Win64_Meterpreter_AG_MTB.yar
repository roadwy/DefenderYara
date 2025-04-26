
rule Backdoor_Win64_Meterpreter_AG_MTB{
	meta:
		description = "Backdoor:Win64/Meterpreter.AG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_03_0 = {c5 cb f3 ff 0f af ?? 41 8b d0 c1 ea 10 } //1
		$a_03_1 = {97 04 00 88 14 01 41 8b d0 ff [0-06] 48 63 0d ?? ?? ?? ?? 48 8b 05 ?? ?? ?? ?? c1 ea 08 88 14 01 ff 05 } //1
		$a_03_2 = {05 ad c0 e1 ff 03 c8 31 ?? ?? ?? ?? ?? 49 81 f9 ?? ?? ?? ?? 0f 8c ?? ?? ff ff } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1+(#a_03_2  & 1)*1) >=3
 
}