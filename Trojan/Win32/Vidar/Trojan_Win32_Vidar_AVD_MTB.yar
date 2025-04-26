
rule Trojan_Win32_Vidar_AVD_MTB{
	meta:
		description = "Trojan:Win32/Vidar.AVD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 02 00 00 "
		
	strings :
		$a_01_0 = {8d 14 1e 29 c2 0f b6 42 15 32 44 1e 29 88 44 1f 15 41 43 } //2
		$a_03_1 = {6b 48 33 1b a1 ?? ?? ?? ?? ff 75 ec ff ?? 6b 48 33 1b a1 ?? ?? ?? ?? ff 75 c8 ff ?? 6b 48 33 1b a1 ?? ?? ?? ?? ff 75 f0 ff } //3
	condition:
		((#a_01_0  & 1)*2+(#a_03_1  & 1)*3) >=5
 
}