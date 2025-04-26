
rule TrojanDropper_Win32_Dofoil_B{
	meta:
		description = "TrojanDropper:Win32/Dofoil.B,SIGNATURE_TYPE_PEHSTR,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {89 85 98 f6 ff ff 89 95 9c f6 ff ff 8b 85 98 f6 ff ff 8b 8d 9c f6 ff ff 89 8d 88 f2 ff ff } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}