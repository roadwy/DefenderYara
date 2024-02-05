
rule Trojan_Win32_Ursnif_ME_MTB{
	meta:
		description = "Trojan:Win32/Ursnif.ME!MTB,SIGNATURE_TYPE_PEHSTR,0a 00 0a 00 02 00 00 05 00 "
		
	strings :
		$a_01_0 = {83 c0 49 b9 b5 a6 ff ff bf b1 ff ff ff 2b fa 2b f9 8d 14 2e 03 c7 83 fa 36 } //05 00 
		$a_01_1 = {8b 5c 24 10 81 c5 84 28 41 01 89 2b } //00 00 
	condition:
		any of ($a_*)
 
}