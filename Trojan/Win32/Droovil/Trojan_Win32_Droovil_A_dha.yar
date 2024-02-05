
rule Trojan_Win32_Droovil_A_dha{
	meta:
		description = "Trojan:Win32/Droovil.A!dha,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {56 6c 61 6b 32 25 78 } //01 00 
		$a_01_1 = {63 6d 64 2e 65 78 65 00 50 4f 53 54 20 2f 25 73 20 48 54 54 50 2f 31 2e 31 } //01 00 
		$a_01_2 = {69 64 3d 00 25 30 33 78 00 00 00 00 26 75 72 69 3d } //00 00 
	condition:
		any of ($a_*)
 
}