
rule Trojan_BAT_NjRat_NEAJ_MTB{
	meta:
		description = "Trojan:BAT/NjRat.NEAJ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,16 00 16 00 06 00 00 "
		
	strings :
		$a_01_0 = {24 31 66 30 62 31 64 35 64 2d 35 33 66 65 2d 34 36 36 66 2d 38 65 61 31 2d 31 64 35 31 35 66 35 65 37 64 64 62 } //5 $1f0b1d5d-53fe-466f-8ea1-1d515f5e7ddb
		$a_01_1 = {73 76 63 68 6f 73 74 2e 4d 79 } //5 svchost.My
		$a_01_2 = {53 6d 61 72 74 41 73 73 65 6d 62 6c 79 2e 48 6f 75 73 65 4f 66 43 61 72 64 73 } //5 SmartAssembly.HouseOfCards
		$a_01_3 = {61 00 73 00 70 00 6e 00 65 00 74 00 5f 00 77 00 70 00 2e 00 65 00 78 00 65 00 } //5 aspnet_wp.exe
		$a_01_4 = {49 6e 76 6f 6b 65 } //1 Invoke
		$a_01_5 = {47 65 74 45 78 65 63 75 74 69 6e 67 41 73 73 65 6d 62 6c 79 } //1 GetExecutingAssembly
	condition:
		((#a_01_0  & 1)*5+(#a_01_1  & 1)*5+(#a_01_2  & 1)*5+(#a_01_3  & 1)*5+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=22
 
}