
rule Trojan_Win32_Vebzenpak_KA_MTB{
	meta:
		description = "Trojan:Win32/Vebzenpak.KA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 0a 00 "
		
	strings :
		$a_03_0 = {8b 1c 17 81 fb 90 01 04 81 fb 90 01 04 31 f3 81 ff 90 01 04 81 fb 90 01 04 01 1c 10 81 fa 90 01 04 81 fb 90 01 04 83 c2 04 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}