
rule Trojan_Win32_BlackMoon_GKT_MTB{
	meta:
		description = "Trojan:Win32/BlackMoon.GKT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0b 00 0b 00 02 00 00 "
		
	strings :
		$a_01_0 = {5c 4c d0 30 1f 64 fd 3f d5 15 34 8e fb 64 45 } //10
		$a_01_1 = {42 6c 61 63 6b 4d 6f 6f 6e 20 52 75 6e 54 69 6d 65 20 45 72 72 6f 72 } //1 BlackMoon RunTime Error
	condition:
		((#a_01_0  & 1)*10+(#a_01_1  & 1)*1) >=11
 
}