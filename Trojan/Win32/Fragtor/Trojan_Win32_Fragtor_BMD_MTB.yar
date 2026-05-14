
rule Trojan_Win32_Fragtor_BMD_MTB{
	meta:
		description = "Trojan:Win32/Fragtor.BMD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 02 00 00 "
		
	strings :
		$a_03_0 = {6a 00 8d 4d fc 51 6a 0c 68 ?? ?? ?? ?? 8b 55 f8 52 ff 15 } //2
		$a_01_1 = {8d 4d fc 51 6a 01 8d 55 08 52 8b 45 f8 50 ff 15 } //2
	condition:
		((#a_03_0  & 1)*2+(#a_01_1  & 1)*2) >=4
 
}