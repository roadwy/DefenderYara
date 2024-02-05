
rule Trojan_Win32_Gozi_MB_MTB{
	meta:
		description = "Trojan:Win32/Gozi.MB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {21 5d fc 51 8b 4d fc 81 c1 08 00 00 00 89 4d fc 59 d3 c0 8a fc 8a e6 d3 cb ff 4d fc 75 f3 90 02 15 aa 49 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}