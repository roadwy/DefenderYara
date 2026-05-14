
rule Trojan_BAT_Jalapeno_QB_MTB{
	meta:
		description = "Trojan:BAT/Jalapeno.QB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 02 00 00 "
		
	strings :
		$a_03_0 = {11 0d 11 00 6f ?? 00 00 0a 17 73 09 00 00 0a 13 02 38 00 00 00 00 00 11 02 02 16 02 8e 69 6f ?? 00 00 0a 38 5b 00 00 00 38 09 00 00 00 20 00 00 00 00 fe 0e 0a 00 fe 0c 0a 00 45 01 00 00 00 4c 00 00 00 fe 0c 0a 00 20 dc 03 00 00 3b e5 ff ff ff 38 39 00 00 00 11 0d 6f ?? 00 00 0a } //4
		$a_01_1 = {24 38 32 35 34 32 33 35 66 2d 32 37 30 65 2d 34 64 39 64 2d 62 38 33 32 2d 34 64 39 63 61 39 39 66 35 32 38 30 } //2 $8254235f-270e-4d9d-b832-4d9ca99f5280
	condition:
		((#a_03_0  & 1)*4+(#a_01_1  & 1)*2) >=6
 
}