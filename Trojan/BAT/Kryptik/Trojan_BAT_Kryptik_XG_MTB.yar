
rule Trojan_BAT_Kryptik_XG_MTB{
	meta:
		description = "Trojan:BAT/Kryptik.XG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,10 00 10 00 04 00 00 "
		
	strings :
		$a_03_0 = {07 11 05 02 11 05 18 5a 18 6f 90 02 04 1f 10 28 90 02 04 9c 00 11 05 17 58 13 05 11 05 06 fe 04 13 06 11 06 2d d7 90 00 } //10
		$a_80_1 = {43 61 6c 6c 42 79 4e 61 6d 65 } //CallByName  2
		$a_80_2 = {4c 61 74 65 42 69 6e 64 69 6e 67 } //LateBinding  2
		$a_00_3 = {49 00 6e 00 a4 06 c6 06 6f 00 6b 00 65 00 } //2
	condition:
		((#a_03_0  & 1)*10+(#a_80_1  & 1)*2+(#a_80_2  & 1)*2+(#a_00_3  & 1)*2) >=16
 
}