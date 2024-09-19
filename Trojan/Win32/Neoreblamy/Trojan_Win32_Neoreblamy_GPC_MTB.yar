
rule Trojan_Win32_Neoreblamy_GPC_MTB{
	meta:
		description = "Trojan:Win32/Neoreblamy.GPC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,10 00 10 00 04 00 00 "
		
	strings :
		$a_01_0 = {56 72 67 63 69 66 51 6c 5a 74 72 75 7a 67 4d 6e 4d } //1 VrgcifQlZtruzgMnM
		$a_01_1 = {4b 6a 64 63 62 43 71 63 61 53 54 75 73 4e 53 4a 57 65 63 77 70 4a 75 } //3 KjdcbCqcaSTusNSJWecwpJu
		$a_01_2 = {49 57 69 77 6a 59 6b 6f 4a 76 51 6e 7a 65 57 41 7a } //5 IWiwjYkoJvQnzeWAz
		$a_01_3 = {64 54 69 48 64 54 4a 76 50 78 64 4c 59 52 } //7 dTiHdTJvPxdLYR
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*3+(#a_01_2  & 1)*5+(#a_01_3  & 1)*7) >=16
 
}