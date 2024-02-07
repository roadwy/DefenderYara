
rule Trojan_Win32_Emotet_DFG_MTB{
	meta:
		description = "Trojan:Win32/Emotet.DFG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 02 00 00 01 00 "
		
	strings :
		$a_00_0 = {59 59 8b 4c 24 14 0f b6 4c 0c 24 03 c1 b9 f1 18 00 00 99 f7 f9 8b 44 24 20 8a 4c 14 24 30 08 } //01 00 
		$a_81_1 = {6a 6c 73 78 49 37 42 69 77 37 73 76 52 6a 7a 68 78 6e 65 38 65 62 64 45 38 73 6e 37 74 73 55 70 68 42 66 36 63 68 } //00 00  jlsxI7Biw7svRjzhxne8ebdE8sn7tsUphBf6ch
	condition:
		any of ($a_*)
 
}