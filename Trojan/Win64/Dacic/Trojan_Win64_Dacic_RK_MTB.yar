
rule Trojan_Win64_Dacic_RK_MTB{
	meta:
		description = "Trojan:Win64/Dacic.RK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 02 00 00 05 00 "
		
	strings :
		$a_01_0 = {8d 42 c3 30 44 15 e0 48 ff c2 48 83 fa 0d 72 f0 } //01 00 
		$a_01_1 = {4e 6f 72 6d 61 6c 69 7a 2e 64 6c 6c } //00 00  Normaliz.dll
	condition:
		any of ($a_*)
 
}