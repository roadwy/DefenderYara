
rule Trojan_Win32_Copak_DC_MTB{
	meta:
		description = "Trojan:Win32/Copak.DC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_01_0 = {39 ff 74 01 ea 31 16 29 df 81 c0 11 f9 d0 8d 81 c6 04 00 00 00 bf 7c 6f a7 29 39 ce 75 } //01 00 
		$a_01_1 = {29 ff 58 46 89 f6 81 c2 01 00 00 00 01 f7 81 fa 70 a6 00 01 75 } //00 00 
	condition:
		any of ($a_*)
 
}