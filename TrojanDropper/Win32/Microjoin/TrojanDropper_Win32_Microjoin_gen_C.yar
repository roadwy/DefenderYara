
rule TrojanDropper_Win32_Microjoin_gen_C{
	meta:
		description = "TrojanDropper:Win32/Microjoin.gen!C,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 "
		
	strings :
		$a_02_0 = {56 68 f4 01 00 00 ?? 8b ?? ?? 84 d2 74 ?? d0 ea 72 ?? d0 ea 72 ?? d0 ea 72 ?? 5a ?? 8b } //2
		$a_02_1 = {b0 5c f2 ae 51 c6 47 ff 00 6a 00 ?? ff } //1
	condition:
		((#a_02_0  & 1)*2+(#a_02_1  & 1)*1) >=3
 
}