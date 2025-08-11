
rule Trojan_Win64_PirateStealer_ABC_MTB{
	meta:
		description = "Trojan:Win64/PirateStealer.ABC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 02 00 00 "
		
	strings :
		$a_01_0 = {48 89 58 10 ba e8 0f 00 00 48 89 c3 48 8b 43 08 48 89 d9 48 01 c1 48 29 f2 48 89 13 48 01 f0 48 89 43 08 31 d2 49 89 f0 48 83 c4 20 5b 5f 5e e9 } //4
		$a_03_1 = {ba 00 10 00 00 31 c9 41 b8 00 30 00 00 41 b9 04 00 00 00 ff 15 ?? ?? ?? 00 48 85 c0 74 } //1
	condition:
		((#a_01_0  & 1)*4+(#a_03_1  & 1)*1) >=5
 
}