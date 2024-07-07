
rule Trojan_Win64_IcedID_GV_MTB{
	meta:
		description = "Trojan:Win64/IcedID.GV!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 06 00 00 "
		
	strings :
		$a_01_0 = {44 6c 6c 52 65 67 69 73 74 65 72 53 65 72 76 65 72 } //1 DllRegisterServer
		$a_01_1 = {50 6c 75 67 69 6e 49 6e 69 74 } //1 PluginInit
		$a_01_2 = {61 66 74 69 6a 79 66 66 69 7a 70 71 72 73 } //1 aftijyffizpqrs
		$a_01_3 = {61 73 6c 77 64 72 7a 64 6d 63 79 72 61 } //1 aslwdrzdmcyra
		$a_01_4 = {62 72 6e 73 72 76 6a 6a 61 } //1 brnsrvjja
		$a_01_5 = {32 31 30 2e 31 32 35 2e 31 36 37 2e 32 34 30 } //1 210.125.167.240
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=6
 
}