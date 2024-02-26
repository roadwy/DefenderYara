
rule Trojan_Win32_CryInfector_MBFH_MTB{
	meta:
		description = "Trojan:Win32/CryInfector.MBFH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0c 00 0c 00 03 00 00 0a 00 "
		
	strings :
		$a_01_0 = {00 2b 33 71 b5 02 00 00 00 c0 2f 40 00 d4 } //01 00 
		$a_01_1 = {2b 40 00 00 f0 30 00 00 ff ff ff 08 00 00 00 01 00 00 00 01 00 00 00 e9 00 00 00 f0 25 40 00 b0 25 40 00 00 16 40 00 78 00 00 00 83 00 00 00 8e } //01 00 
		$a_01_2 = {4f 66 66 69 63 65 53 61 66 65 00 4f 66 66 69 63 65 53 61 66 65 00 00 4f 66 66 69 63 65 53 61 66 } //00 00  晏楦散慓敦伀晦捩卥晡e伀晦捩卥晡
	condition:
		any of ($a_*)
 
}