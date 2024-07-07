
rule Trojan_BAT_Bandra_GTA_MTB{
	meta:
		description = "Trojan:BAT/Bandra.GTA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0c 00 0c 00 03 00 00 "
		
	strings :
		$a_01_0 = {11 06 12 11 58 11 06 25 1f 3b 5c 1f 3b 5a 59 1f 38 58 11 06 12 11 58 46 61 52 11 06 17 58 13 06 11 06 1f 11 37 da } //10
		$a_01_1 = {56 69 72 74 75 61 6c 50 72 6f 74 65 63 74 } //1 VirtualProtect
		$a_01_2 = {50 72 6f 6a 65 63 74 33 35 2e 65 78 65 } //1 Project35.exe
	condition:
		((#a_01_0  & 1)*10+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=12
 
}