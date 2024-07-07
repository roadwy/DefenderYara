
rule Trojan_Win64_CobaltStrike_RCB_MTB{
	meta:
		description = "Trojan:Win64/CobaltStrike.RCB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 02 00 00 "
		
	strings :
		$a_01_0 = {66 35 37 34 64 32 39 39 39 34 61 33 61 64 63 36 38 64 63 62 64 32 61 33 39 35 39 36 33 33 31 37 31 33 39 35 37 37 33 34 2e 62 69 6e 2e 70 61 63 6b 65 64 2e 64 6c 6c } //1 f574d29994a3adc68dcbd2a39596331713957734.bin.packed.dll
		$a_01_1 = {48 89 d0 48 83 f0 ff 48 09 c8 49 89 c8 49 83 f0 ff 49 21 d0 49 89 c9 49 21 d1 49 83 f1 ff 48 09 d1 4c 01 c0 4c 29 c8 48 01 c8 } //5
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*5) >=6
 
}