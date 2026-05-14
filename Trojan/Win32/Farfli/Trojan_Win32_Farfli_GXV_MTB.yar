
rule Trojan_Win32_Farfli_GXV_MTB{
	meta:
		description = "Trojan:Win32/Farfli.GXV!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0b 00 0b 00 03 00 00 "
		
	strings :
		$a_01_0 = {84 d1 33 d9 3b f4 f9 66 85 de 03 f9 } //5
		$a_01_1 = {fe c8 f6 d0 f8 3b cb 32 d8 f8 88 14 04 } //5
		$a_01_2 = {54 62 73 41 70 70 49 6e 73 74 61 6e 63 65 } //1 TbsAppInstance
	condition:
		((#a_01_0  & 1)*5+(#a_01_1  & 1)*5+(#a_01_2  & 1)*1) >=11
 
}