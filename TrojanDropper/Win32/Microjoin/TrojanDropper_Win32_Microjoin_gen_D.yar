
rule TrojanDropper_Win32_Microjoin_gen_D{
	meta:
		description = "TrojanDropper:Win32/Microjoin.gen!D,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {68 f4 01 00 00 90 90 [0-04] 55 8b 4b 1c 84 d2 74 ?? [0-04] d0 ea 72 ?? [0-04] d0 ea 72 ?? [0-04] d0 ea 72 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}