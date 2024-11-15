
rule Trojan_BAT_Zusy_NK_MTB{
	meta:
		description = "Trojan:BAT/Zusy.NK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 03 00 00 "
		
	strings :
		$a_03_0 = {11 00 17 64 13 00 ?? ?? 00 00 00 11 01 11 00 11 04 17 59 5f 59 13 01 } //2
		$a_01_1 = {11 03 11 07 d2 6e 1e 11 06 5a 1f 3f 5f 62 60 13 03 } //2
		$a_81_2 = {54 79 72 6f 6e 65 2e 64 6c 6c } //1 Tyrone.dll
	condition:
		((#a_03_0  & 1)*2+(#a_01_1  & 1)*2+(#a_81_2  & 1)*1) >=5
 
}
rule Trojan_BAT_Zusy_NK_MTB_2{
	meta:
		description = "Trojan:BAT/Zusy.NK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 05 00 00 "
		
	strings :
		$a_81_0 = {32 61 39 64 37 39 36 32 2d 33 35 36 36 2d 33 32 39 36 2d 39 38 39 37 2d 31 33 38 32 33 33 31 32 35 31 37 31 } //2 2a9d7962-3566-3296-9897-138233125171
		$a_81_1 = {73 65 74 5f 55 73 65 53 68 65 6c 6c 45 78 65 63 75 74 65 } //1 set_UseShellExecute
		$a_81_2 = {4b 6f 69 2e 50 72 6f 70 65 72 74 69 65 73 } //1 Koi.Properties
		$a_81_3 = {56 69 72 74 75 61 6c 41 6c 6c 6f 63 45 78 } //1 VirtualAllocEx
		$a_81_4 = {73 65 74 74 69 6e 67 73 5c 73 68 6f 70 5c 74 79 70 65 2e 74 78 74 } //1 settings\shop\type.txt
	condition:
		((#a_81_0  & 1)*2+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1) >=6
 
}