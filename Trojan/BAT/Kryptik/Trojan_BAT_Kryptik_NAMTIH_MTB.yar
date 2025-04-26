
rule Trojan_BAT_Kryptik_NAMTIH_MTB{
	meta:
		description = "Trojan:BAT/Kryptik.NAMTIH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,09 00 09 00 04 00 00 "
		
	strings :
		$a_01_0 = {66 65 74 69 73 68 46 6f 6f 74 } //2 fetishFoot
		$a_01_1 = {67 70 6c 65 65 66 66 } //2 gpleeff
		$a_01_2 = {4c 55 6d 69 6f 65 72 72 73 64 66 } //3 LUmioerrsdf
		$a_01_3 = {00 46 75 6b 61 6e 74 75 00 } //2
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2+(#a_01_2  & 1)*3+(#a_01_3  & 1)*2) >=9
 
}