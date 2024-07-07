
rule Trojan_BAT_AveMaria_RDD_MTB{
	meta:
		description = "Trojan:BAT/AveMaria.RDD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {36 33 63 35 34 61 39 34 2d 62 65 64 32 2d 34 35 33 65 2d 38 61 33 39 2d 65 64 39 64 63 38 61 37 30 36 31 38 } //1 63c54a94-bed2-453e-8a39-ed9dc8a70618
		$a_01_1 = {41 73 64 62 75 67 65 20 46 61 63 6b 61 } //1 Asdbuge Facka
		$a_01_2 = {41 54 4d 5f 73 69 6d 75 6c 61 74 69 6f 6e } //1 ATM_simulation
		$a_01_3 = {43 61 6e 6e 6f 6e 5f 53 69 6d 75 6c 61 74 69 6f 6e } //1 Cannon_Simulation
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}