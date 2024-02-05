
rule Trojan_Win32_Gozi_RPR_MTB{
	meta:
		description = "Trojan:Win32/Gozi.RPR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_02_0 = {81 fe c3 14 0c 18 89 2d 90 01 04 7c c6 90 09 25 00 90 02 20 55 55 55 55 55 ff 15 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}