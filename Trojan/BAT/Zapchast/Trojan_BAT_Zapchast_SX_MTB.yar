
rule Trojan_BAT_Zapchast_SX_MTB{
	meta:
		description = "Trojan:BAT/Zapchast.SX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,29 00 29 00 05 00 00 "
		
	strings :
		$a_80_0 = {50 72 6f 63 65 73 73 20 48 6f 6c 6c 6f 77 69 6e 67 } //Process Hollowing  20
		$a_80_1 = {5b 45 4e 49 5d 5b 48 4f 4c 4c 4f 57 5d 20 53 70 61 77 6e 69 6e 67 20 72 65 67 61 73 6d } //[ENI][HOLLOW] Spawning regasm  10
		$a_80_2 = {5b 45 4e 49 5d 5b 50 41 59 4c 4f 41 44 5d } //[ENI][PAYLOAD]  5
		$a_80_3 = {5b 45 4e 49 5d 5b 41 4d 53 49 5d 20 62 6c 69 6e 64 } //[ENI][AMSI] blind  5
		$a_80_4 = {5b 45 4e 49 5d 5b 49 41 54 5d 20 52 65 73 6f 6c 76 65 64 } //[ENI][IAT] Resolved  1
	condition:
		((#a_80_0  & 1)*20+(#a_80_1  & 1)*10+(#a_80_2  & 1)*5+(#a_80_3  & 1)*5+(#a_80_4  & 1)*1) >=41
 
}