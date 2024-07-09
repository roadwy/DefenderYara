
rule HackTool_BAT_Binder_gen_C{
	meta:
		description = "HackTool:BAT/Binder.gen!C,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a0 = {16 02 8e b7 17 da 0d 0c 2b 12 02 08 02 08 91 (06|07) 08 (06|07) 8e b7 5d 91 61 9c 08 17 d6 0c 08 09 31 ea 02 (|) 0a 0b 2b 00 (06|07) 2a } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}