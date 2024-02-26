
rule Trojan_Win32_Copak_KAK_MTB{
	meta:
		description = "Trojan:Win32/Copak.KAK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 0a 00 "
		
	strings :
		$a_03_0 = {8b 06 21 ff 29 ca 81 e0 90 01 04 b9 90 01 04 bf 90 01 04 31 03 81 e9 90 01 04 bf 90 01 04 43 81 c7 90 01 04 bf 90 01 04 46 01 d7 81 ef 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}