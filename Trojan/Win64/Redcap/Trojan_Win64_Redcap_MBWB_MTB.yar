
rule Trojan_Win64_Redcap_MBWB_MTB{
	meta:
		description = "Trojan:Win64/Redcap.MBWB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0b 00 0b 00 03 00 00 "
		
	strings :
		$a_01_0 = {41 e1 c1 07 e6 d6 18 e6 70 61 74 68 09 63 6f 6d 6d 61 6e 64 2d 6c 69 6e 65 2d 61 72 67 75 6d 65 6e 74 73 0a 64 65 70 09 67 69 74 68 75 62 2e 63 6f 6d 2f 6d 69 74 72 65 2f 6d 61 6e 78 2f 73 68 65 6c 6c 73 09 28 64 65 76 65 6c 29 09 0a 62 75 69 6c 64 } //10
		$a_01_1 = {36 67 45 44 78 35 56 49 51 5f 54 38 38 76 4d 37 49 7a 6b 54 2f 63 53 } //1 6gEDx5VIQ_T88vM7IzkT/cS
		$a_01_2 = {64 2d 58 67 38 4c 68 65 32 35 41 43 4e 50 2d 56 39 79 49 4f 2f 39 67 } //1 d-Xg8Lhe25ACNP-V9yIO/9g
	condition:
		((#a_01_0  & 1)*10+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=11
 
}