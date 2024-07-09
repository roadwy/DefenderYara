
rule Trojan_Win32_Vidar_AMMB_MTB{
	meta:
		description = "Trojan:Win32/Vidar.AMMB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 02 00 00 "
		
	strings :
		$a_03_0 = {81 ec 08 08 00 00 a1 ?? ?? ?? ?? 33 c4 89 84 24 04 08 00 00 81 3d ?? ?? ?? ?? c7 0f 00 00 } //2
		$a_03_1 = {30 04 33 83 ff ?? 75 } //2
	condition:
		((#a_03_0  & 1)*2+(#a_03_1  & 1)*2) >=4
 
}