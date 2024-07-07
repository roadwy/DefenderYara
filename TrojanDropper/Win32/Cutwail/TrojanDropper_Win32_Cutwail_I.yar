
rule TrojanDropper_Win32_Cutwail_I{
	meta:
		description = "TrojanDropper:Win32/Cutwail.I,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {56 56 68 00 24 a4 9c 57 ff 15 90 01 02 00 01 57 ff 15 90 01 02 00 01 eb 28 68 90 01 02 00 01 50 e8 90 01 02 ff ff 6a 90 00 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}