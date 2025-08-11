
rule Trojan_BAT_DaVinci_MBZ_MTB{
	meta:
		description = "Trojan:BAT/DaVinci.MBZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 "
		
	strings :
		$a_01_0 = {6e 00 65 00 74 00 2e 00 61 00 6c 00 70 00 68 00 61 00 00 13 67 00 68 00 6f 00 73 00 74 00 2e 00 64 00 6c 00 6c 00 00 17 70 00 68 00 61 00 6e 00 74 00 6f 00 6d 00 2e 00 65 00 78 } //2
		$a_01_1 = {44 6f 41 6e 43 61 4e 68 61 6e } //1 DoAnCaNhan
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*1) >=3
 
}