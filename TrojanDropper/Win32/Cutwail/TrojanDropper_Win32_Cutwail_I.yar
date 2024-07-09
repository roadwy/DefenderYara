
rule TrojanDropper_Win32_Cutwail_I{
	meta:
		description = "TrojanDropper:Win32/Cutwail.I,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {56 56 68 00 24 a4 9c 57 ff 15 ?? ?? 00 01 57 ff 15 ?? ?? 00 01 eb 28 68 ?? ?? 00 01 50 e8 ?? ?? ff ff 6a } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}