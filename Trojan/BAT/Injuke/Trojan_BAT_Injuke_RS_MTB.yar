
rule Trojan_BAT_Injuke_RS_MTB{
	meta:
		description = "Trojan:BAT/Injuke.RS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_81_0 = {53 79 73 74 65 6d 2e 4c 6f 67 69 73 74 69 63 73 2e 64 6c 6c } //1 System.Logistics.dll
		$a_81_1 = {43 6f 72 65 20 6c 6f 67 69 73 74 69 63 73 20 66 72 61 6d 65 77 6f 72 6b 20 61 6e 64 20 6f 70 65 72 61 74 69 6f 6e 73 20 6c 69 62 72 61 72 79 } //1 Core logistics framework and operations library
		$a_81_2 = {50 75 62 6c 69 63 4b 65 79 54 6f 6b 65 6e 3d 62 37 37 61 35 63 35 36 31 39 33 34 65 30 38 } //1 PublicKeyToken=b77a5c561934e08
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1) >=3
 
}