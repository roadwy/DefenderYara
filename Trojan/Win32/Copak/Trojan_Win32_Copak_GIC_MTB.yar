
rule Trojan_Win32_Copak_GIC_MTB{
	meta:
		description = "Trojan:Win32/Copak.GIC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 0a 00 "
		
	strings :
		$a_03_0 = {b8 0d 5d 42 9e 31 1f 47 50 8b 04 24 83 c4 04 89 c1 39 f7 75 dc 81 e9 90 01 04 89 c0 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}