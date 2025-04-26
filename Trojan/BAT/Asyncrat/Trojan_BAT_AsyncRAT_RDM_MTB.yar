
rule Trojan_BAT_AsyncRAT_RDM_MTB{
	meta:
		description = "Trojan:BAT/AsyncRAT.RDM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {36 32 30 33 35 38 33 61 2d 66 66 35 32 2d 34 33 33 39 2d 39 63 39 30 2d 64 33 37 37 31 37 39 61 66 64 31 63 } //1 6203583a-ff52-4339-9c90-d377179afd1c
		$a_01_1 = {52 65 63 6f 52 65 61 63 74 6f 72 } //1 RecoReactor
		$a_01_2 = {6a 70 65 65 51 30 49 77 78 57 6b 74 71 42 78 6f 37 61 2e 6d 30 69 73 49 5a 31 75 30 64 75 57 32 38 6e 33 44 35 } //1 jpeeQ0IwxWktqBxo7a.m0isIZ1u0duW28n3D5
		$a_01_3 = {6b 53 6d 6e 57 6c 4a 50 48 46 56 51 44 42 6a 64 31 41 2e 54 76 63 4f 4a 31 47 6e 6c 46 61 4f 45 32 6c 54 76 55 } //1 kSmnWlJPHFVQDBjd1A.TvcOJ1GnlFaOE2lTvU
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}