
rule Trojan_Win32_SmokeLdr_GJ_MTB{
	meta:
		description = "Trojan:Win32/SmokeLdr.GJ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0b 00 0b 00 02 00 00 "
		
	strings :
		$a_02_0 = {30 0c 1e 83 ff 90 01 01 90 18 46 3b f7 90 18 81 3d 90 01 08 90 18 a1 90 01 04 69 c0 90 01 04 05 90 01 04 a3 90 01 04 8a 0d 90 00 } //10
		$a_02_1 = {88 0c 32 3d 03 02 00 00 90 18 46 3b f0 90 18 8b 15 90 01 04 8a 8c 32 90 01 04 8b 15 90 00 } //1
	condition:
		((#a_02_0  & 1)*10+(#a_02_1  & 1)*1) >=11
 
}