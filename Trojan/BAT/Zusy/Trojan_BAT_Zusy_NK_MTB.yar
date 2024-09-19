
rule Trojan_BAT_Zusy_NK_MTB{
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