
rule Trojan_Win32_Astaroth_psyQ_MTB{
	meta:
		description = "Trojan:Win32/Astaroth.psyQ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 01 00 00 07 00 "
		
	strings :
		$a_01_0 = {ff 15 54 f1 40 00 eb 43 02 03 02 03 03 03 02 03 03 02 03 02 03 03 03 02 03 c7 45 f4 97 00 00 00 ff 75 d8 eb d1 } //00 00 
	condition:
		any of ($a_*)
 
}