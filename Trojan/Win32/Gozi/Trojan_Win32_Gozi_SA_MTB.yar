
rule Trojan_Win32_Gozi_SA_MTB{
	meta:
		description = "Trojan:Win32/Gozi.SA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {81 c7 80 bb bf 01 90 02 10 89 7d 00 83 c5 04 ff 4c 24 18 bb e0 ff 00 00 90 02 10 89 6c 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}