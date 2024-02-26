
rule Trojan_BAT_LummaStealer_CCHI_MTB{
	meta:
		description = "Trojan:BAT/LummaStealer.CCHI!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 01 00 "
		
	strings :
		$a_01_0 = {52 00 41 00 4e 00 be 03 c0 03 c0 03 bf 03 bc 03 b9 03 b6 03 b7 03 b5 03 b7 03 b4 03 c3 03 c5 03 bb 03 b9 03 c4 03 c8 03 49 00 42 00 4b 00 49 00 4e } //01 00 
		$a_01_1 = {bc 03 b7 03 b9 03 ba 03 bd 03 c8 03 b5 03 b7 03 b5 03 bd 03 c5 03 b7 03 b5 03 b7 03 bb 03 bc 03 } //01 00 
		$a_01_2 = {bc 03 b6 03 c0 03 c0 03 c5 03 bd 03 c1 03 c8 03 b3 03 bd 03 c4 03 c5 03 c0 03 c7 03 c5 03 b9 03 c8 03 bb 03 c8 03 be 03 bc 03 bd 03 bc 03 c3 03 b9 03 c4 03 be 03 be 03 b7 03 c7 03 c4 03 } //01 00 
		$a_01_3 = {b2 03 c8 03 c6 03 b7 03 bc 03 be 03 bc 03 bf 03 c7 03 b3 03 6f 00 76 00 bc 03 b5 03 bd 03 bf 03 b6 03 bb 03 b1 03 c5 03 b9 03 b7 03 bf 03 b3 03 c0 03 bf 03 c0 03 bf 03 c3 03 } //01 00 
		$a_01_4 = {b7 03 ba 03 bf 03 b9 03 c6 03 b7 03 bc 03 bd 03 bc 03 b6 03 be 03 bc 03 b6 03 bc 03 bc 03 bd 03 be 03 bd 03 c7 03 b4 03 c7 03 c0 03 bb 03 bc 03 c3 03 } //00 00 
	condition:
		any of ($a_*)
 
}