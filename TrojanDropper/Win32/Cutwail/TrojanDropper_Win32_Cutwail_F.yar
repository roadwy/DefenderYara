
rule TrojanDropper_Win32_Cutwail_F{
	meta:
		description = "TrojanDropper:Win32/Cutwail.F,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {ff 35 f8 23 40 00 ff 15 ?? ?? 40 00 c7 86 b0 00 00 00 (2a|3a) 10 40 00 56 ff 35 f8 23 40 00 ff 15 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}