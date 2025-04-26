
rule Trojan_BAT_NjRat_NEDN_MTB{
	meta:
		description = "Trojan:BAT/NjRat.NEDN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0c 00 0c 00 05 00 00 "
		
	strings :
		$a_01_0 = {36 31 66 35 36 61 39 34 2d 63 38 32 64 2d 34 63 61 61 2d 38 33 39 62 2d 31 39 37 35 32 61 34 31 66 65 33 38 } //5 61f56a94-c82d-4caa-839b-19752a41fe38
		$a_01_1 = {56 00 49 00 50 00 20 00 54 00 6f 00 6f 00 6c 00 73 00 61 00 73 00 73 00 65 00 6d 00 62 00 6c 00 79 00 63 00 68 00 61 00 6e 00 67 00 65 00 2e 00 65 00 78 00 65 00 } //2 VIP Toolsassemblychange.exe
		$a_01_2 = {5f 00 45 00 6e 00 63 00 72 00 79 00 70 00 74 00 65 00 64 00 24 00 } //2 _Encrypted$
		$a_01_3 = {42 79 20 46 49 47 48 54 45 52 } //2 By FIGHTER
		$a_01_4 = {53 6d 61 72 74 41 73 73 65 6d 62 6c 79 2e 48 6f 75 73 65 4f 66 43 61 72 64 73 } //1 SmartAssembly.HouseOfCards
	condition:
		((#a_01_0  & 1)*5+(#a_01_1  & 1)*2+(#a_01_2  & 1)*2+(#a_01_3  & 1)*2+(#a_01_4  & 1)*1) >=12
 
}