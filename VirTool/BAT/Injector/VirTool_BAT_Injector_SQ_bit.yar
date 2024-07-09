
rule VirTool_BAT_Injector_SQ_bit{
	meta:
		description = "VirTool:BAT/Injector.SQ!bit,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {68 00 75 00 69 00 5a 00 64 00 6b 00 6d 00 6b 00 49 00 77 00 49 00 49 00 72 00 42 00 } //1 huiZdkmkIwIIrB
		$a_03_1 = {08 07 8e 69 17 59 2e 1e 7e ?? ?? ?? ?? 7e ?? ?? ?? ?? 07 08 91 1f ?? 61 d2 9c 7e ?? ?? ?? ?? 17 58 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}