
rule Trojan_Win32_Alien_GMO_MTB{
	meta:
		description = "Trojan:Win32/Alien.GMO!MTB,SIGNATURE_TYPE_PEHSTR_EXT,15 00 15 00 03 00 00 "
		
	strings :
		$a_03_0 = {57 42 22 c3 0e ba ?? ?? ?? ?? 5f ab 30 d7 42 6c 36 bf ?? ?? ?? ?? 40 e5 a6 08 ca 0a c8 } //10
		$a_03_1 = {6a b7 08 47 a4 35 ?? ?? ?? ?? 14 57 } //10
		$a_80_2 = {4f 70 74 69 4c 61 75 6e 63 68 65 72 55 } //OptiLauncherU  1
	condition:
		((#a_03_0  & 1)*10+(#a_03_1  & 1)*10+(#a_80_2  & 1)*1) >=21
 
}