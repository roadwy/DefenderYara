
rule HackTool_BAT_Injector_A{
	meta:
		description = "HackTool:BAT/Injector.A,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {07 08 07 8e 69 5d 91 08 06 58 07 8e 69 58 1f 1f 5f 63 20 ff 00 00 00 5f d2 61 d2 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}