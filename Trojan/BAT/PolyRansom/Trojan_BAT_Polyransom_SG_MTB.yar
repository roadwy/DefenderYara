
rule Trojan_BAT_Polyransom_SG_MTB{
	meta:
		description = "Trojan:BAT/Polyransom.SG!MTB,SIGNATURE_TYPE_PEHSTR,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {73 65 74 5f 55 73 65 53 68 65 6c 6c 45 78 65 63 75 74 65 } //02 00  set_UseShellExecute
		$a_01_1 = {53 68 69 77 57 69 6e 64 6f 77 } //01 00  ShiwWindow
		$a_01_2 = {47 65 74 45 78 65 63 75 74 69 6e 67 41 73 73 65 6d 62 6c 79 } //00 00  GetExecutingAssembly
	condition:
		any of ($a_*)
 
}