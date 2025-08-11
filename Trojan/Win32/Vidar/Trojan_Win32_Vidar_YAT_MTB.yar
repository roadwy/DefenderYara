
rule Trojan_Win32_Vidar_YAT_MTB{
	meta:
		description = "Trojan:Win32/Vidar.YAT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0b 00 0b 00 02 00 00 "
		
	strings :
		$a_03_0 = {03 fd 81 f2 ?? ?? ?? ?? 03 f0 2b d5 87 c7 f7 d6 87 f0 33 fe c1 c8 } //1
		$a_03_1 = {2b f9 31 05 ?? ?? ?? ?? 33 d0 c1 c7 0a 8b fe } //10
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*10) >=11
 
}