
rule TrojanDropper_Win32_Astercax_A{
	meta:
		description = "TrojanDropper:Win32/Astercax.A,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {83 e8 4f 0f 80 a6 04 00 00 50 8d 47 50 50 6a 28 ff 15 ?? ?? 40 00 6a 01 6a 01 ff 15 ?? ?? 40 00 83 e8 27 0f 80 86 04 00 00 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}