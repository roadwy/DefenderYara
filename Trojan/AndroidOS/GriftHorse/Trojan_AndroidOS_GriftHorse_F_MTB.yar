
rule Trojan_AndroidOS_GriftHorse_F_MTB{
	meta:
		description = "Trojan:AndroidOS/GriftHorse.F!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_03_0 = {38 03 25 00 1a 00 ?? ?? 6e 20 ?? ?? 03 00 0a 01 1a 02 ?? ?? 38 01 06 00 6e 30 ?? ?? 03 02 0c 03 6e 20 ?? ?? 23 00 0a 00 39 00 11 00 22 00 ?? ?? 70 10 ?? ?? 00 00 6e 20 ?? ?? 20 00 6e 20 ?? ?? 30 00 6e 10 ?? ?? 00 00 0c 03 71 00 ?? ?? 00 00 0c 00 22 01 ?? ?? 70 10 ?? ?? 01 00 6e 20 ?? ?? 31 00 1a 03 ?? ?? 6e 20 ?? ?? 31 00 6e 20 ?? ?? 01 00 1a 03 ?? ?? 6e 20 ?? ?? 31 00 71 00 ?? ?? 00 00 0c 03 6e 20 ?? ?? 31 00 6e 10 ?? ?? 01 00 0c 03 } //1
		$a_00_1 = {63 6f 6d 2f 67 65 6e 65 72 61 6c 66 6c 6f 77 2f 62 72 69 64 67 65 } //1 com/generalflow/bridge
		$a_00_2 = {43 6f 6e 73 74 72 75 63 74 55 52 4c } //1 ConstructURL
		$a_00_3 = {70 6f 72 74 61 6c 55 52 4c } //1 portalURL
		$a_00_4 = {77 69 74 68 46 43 4d 4e 6f 74 69 66 69 63 61 74 69 6f 6e } //1 withFCMNotification
	condition:
		((#a_03_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1) >=5
 
}