
rule Trojan_Win32_IcedID_VDSK_MTB{
	meta:
		description = "Trojan:Win32/IcedID.VDSK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_02_0 = {2b cd 83 e9 09 0f b7 f9 05 dc a5 ed 01 a3 ?? ?? ?? ?? 89 02 90 09 06 00 8b 0d } //2
		$a_02_1 = {8b 55 f8 8b ca b8 05 00 00 00 03 c1 83 e8 05 89 45 fc a1 ?? ?? ?? ?? 8b 4d fc 89 08 } //2
	condition:
		((#a_02_0  & 1)*2+(#a_02_1  & 1)*2) >=2
 
}