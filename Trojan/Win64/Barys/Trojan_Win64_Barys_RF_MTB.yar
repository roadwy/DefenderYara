
rule Trojan_Win64_Barys_RF_MTB{
	meta:
		description = "Trojan:Win64/Barys.RF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {67 57 6b 63 62 53 4b 6a 72 53 68 64 45 6d 59 4e } //1 gWkcbSKjrShdEmYN
		$a_01_1 = {4b 70 31 31 30 4d 50 49 51 64 41 4a 52 35 71 71 } //1 Kp110MPIQdAJR5qq
		$a_01_2 = {34 64 64 31 62 32 33 65 2d 66 62 38 64 2d 34 39 62 65 2d 61 32 30 65 2d 34 39 61 65 61 36 39 65 62 37 38 32 } //1 4dd1b23e-fb8d-49be-a20e-49aea69eb782
		$a_01_3 = {50 30 4e 2a 52 24 54 } //1 P0N*R$T
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}