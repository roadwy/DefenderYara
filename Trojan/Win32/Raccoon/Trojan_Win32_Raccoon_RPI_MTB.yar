
rule Trojan_Win32_Raccoon_RPI_MTB{
	meta:
		description = "Trojan:Win32/Raccoon.RPI!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {83 c6 01 8a 46 ff 68 90 01 04 83 c4 04 32 02 68 90 01 04 83 c4 04 aa 68 90 01 04 83 c4 04 83 c2 01 68 90 01 04 83 c4 04 68 90 01 04 83 c4 04 49 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}