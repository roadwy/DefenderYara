
rule Trojan_BAT_BlueFox_RDA_MTB{
	meta:
		description = "Trojan:BAT/BlueFox.RDA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {66 63 31 66 38 31 64 61 64 33 30 } //1 fc1f81dad30
		$a_01_1 = {42 00 6c 00 75 00 65 00 46 00 6f 00 78 00 } //1 BlueFox
		$a_01_2 = {73 65 74 5f 55 73 65 53 68 65 6c 6c 45 78 65 63 75 74 65 } //1 set_UseShellExecute
		$a_01_3 = {64 37 61 61 38 30 63 39 64 63 64 } //1 d7aa80c9dcd
		$a_01_4 = {37 32 62 32 36 65 32 33 65 64 34 } //1 72b26e23ed4
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}