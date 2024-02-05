
rule TrojanDropper_Win32_Ethersh_gen_A{
	meta:
		description = "TrojanDropper:Win32/Ethersh.gen!A,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_01_0 = {8a 07 2c 63 34 42 34 63 f6 d0 88 07 47 e2 f1 } //00 00 
	condition:
		any of ($a_*)
 
}