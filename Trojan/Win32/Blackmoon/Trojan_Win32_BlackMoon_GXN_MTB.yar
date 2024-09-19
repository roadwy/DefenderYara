
rule Trojan_Win32_BlackMoon_GXN_MTB{
	meta:
		description = "Trojan:Win32/BlackMoon.GXN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0b 00 0b 00 02 00 00 "
		
	strings :
		$a_03_0 = {00 fd 67 41 00 fd 67 41 00 98 ?? ?? ?? ?? 68 ?? ?? ?? ?? 41 00 f9 68 ?? ?? ?? ?? 41 00 78 69 41 00 66 69 41 00 78 69 41 00 a0 69 41 00 a0 } //10
		$a_01_1 = {42 6c 61 63 6b 4d 6f 6f 6e 20 52 75 6e 54 69 6d 65 20 45 72 72 6f 72 } //1 BlackMoon RunTime Error
	condition:
		((#a_03_0  & 1)*10+(#a_01_1  & 1)*1) >=11
 
}