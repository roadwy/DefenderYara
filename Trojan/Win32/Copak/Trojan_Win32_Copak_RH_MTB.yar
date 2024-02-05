
rule Trojan_Win32_Copak_RH_MTB{
	meta:
		description = "Trojan:Win32/Copak.RH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_01_0 = {81 fa f4 01 00 00 75 05 ba 00 00 00 00 c3 2b e2 58 68 4e 3f 3e de 5f c3 } //00 00 
	condition:
		any of ($a_*)
 
}