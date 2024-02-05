
rule Trojan_Win32_Nedsym_A{
	meta:
		description = "Trojan:Win32/Nedsym.A,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {ff 57 0c ff 75 94 68 90 01 02 42 00 ff 75 f0 68 90 01 02 42 00 8d 45 e8 ba 05 00 00 00 e8 90 01 02 fd ff 46 ff 4d d8 0f 85 90 01 01 fd ff ff 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}