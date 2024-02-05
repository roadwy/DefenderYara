
rule Trojan_BAT_Nanocore_AC_MTB{
	meta:
		description = "Trojan:BAT/Nanocore.AC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {67 65 74 5f 4f 66 66 73 65 74 4d 61 72 73 68 61 6c 65 72 00 67 65 74 5f 52 65 74 75 72 6e 4d 65 73 73 61 67 65 00 4f 66 66 73 65 74 4d 61 72 73 68 61 6c 65 72 00 52 65 74 75 72 6e 4d 65 73 73 61 67 65 } //01 00 
		$a_01_1 = {67 65 74 5f 54 65 78 74 00 73 65 74 5f 54 65 78 74 } //01 00 
		$a_01_2 = {73 73 73 73 73 00 52 65 76 65 72 73 65 } //00 00 
	condition:
		any of ($a_*)
 
}