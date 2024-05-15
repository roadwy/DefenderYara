
rule Trojan_Win32_Ekstak_ASFI_MTB{
	meta:
		description = "Trojan:Win32/Ekstak.ASFI!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 05 00 "
		
	strings :
		$a_03_0 = {6a 00 6a 00 6a 01 56 ff 15 90 01 02 65 00 68 90 01 02 65 00 6a 00 8d 4c 24 10 6a 01 51 c7 44 24 18 0c 00 00 00 89 74 24 1c c7 44 24 20 00 00 00 00 ff 15 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}