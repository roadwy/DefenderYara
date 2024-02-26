
rule Trojan_Win32_Bodegun_GNF_MTB{
	meta:
		description = "Trojan:Win32/Bodegun.GNF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 0a 00 "
		
	strings :
		$a_01_0 = {8b d0 83 e2 07 8a 4c 15 f8 30 0c 06 8d 54 15 f8 80 c1 1d 40 88 0a 3b c7 } //00 00 
	condition:
		any of ($a_*)
 
}