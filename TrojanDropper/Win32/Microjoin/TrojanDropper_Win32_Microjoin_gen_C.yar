
rule TrojanDropper_Win32_Microjoin_gen_C{
	meta:
		description = "TrojanDropper:Win32/Microjoin.gen!C,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 "
		
	strings :
		$a_02_0 = {56 68 f4 01 00 00 90 01 01 8b 90 01 02 84 d2 74 90 01 01 d0 ea 72 90 01 01 d0 ea 72 90 01 01 d0 ea 72 90 01 01 5a 90 01 01 8b 90 00 } //2
		$a_02_1 = {b0 5c f2 ae 51 c6 47 ff 00 6a 00 90 01 01 ff 90 00 } //1
	condition:
		((#a_02_0  & 1)*2+(#a_02_1  & 1)*1) >=3
 
}