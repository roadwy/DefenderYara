
rule Trojan_Win32_flystudio_KA_MTB{
	meta:
		description = "Trojan:Win32/flystudio.KA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {73 68 75 6e 71 69 61 6e 2e 74 6f 6f 6f 2e 74 6f 70 } //01 00 
		$a_01_1 = {55 73 65 72 73 5c 50 75 62 6c 69 63 5c 78 69 61 6f 64 61 78 7a 71 78 69 61 } //01 00 
		$a_01_2 = {48 74 74 70 4f 70 65 6e 52 65 71 75 65 73 74 41 } //00 00 
	condition:
		any of ($a_*)
 
}