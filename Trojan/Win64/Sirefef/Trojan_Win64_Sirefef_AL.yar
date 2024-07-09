
rule Trojan_Win64_Sirefef_AL{
	meta:
		description = "Trojan:Win64/Sirefef.AL,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 02 00 00 "
		
	strings :
		$a_03_0 = {ba 09 00 00 00 48 8b cb c7 45 ?? a8 01 00 00 48 c7 45 ?? 00 00 00 60 c7 45 ?? 01 00 00 00 c7 45 ?? 40 00 00 00 ff 15 ?? ?? ?? ?? 85 c0 74 ?? ff 15 ?? ?? ?? ?? 85 c0 74 01 cc } //1
		$a_01_1 = {38 30 30 30 30 30 63 62 2e 40 } //1 800000cb.@
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1) >=1
 
}