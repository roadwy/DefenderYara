
rule Trojan_Win32_BlackMoon_GXU_MTB{
	meta:
		description = "Trojan:Win32/BlackMoon.GXU!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0b 00 0b 00 02 00 00 "
		
	strings :
		$a_03_0 = {8b ce c7 44 24 38 47 65 74 50 c7 44 24 3c 72 6f 63 41 c7 44 24 40 64 64 72 65 66 c7 44 24 44 73 73 c6 44 24 46 00 e8 ?? ?? ?? ?? 89 44 24 28 85 c0 0f 84 } //10
		$a_01_1 = {42 6c 61 63 6b 4d 6f 6f 6e 20 52 75 6e 54 69 6d 65 } //1 BlackMoon RunTime
	condition:
		((#a_03_0  & 1)*10+(#a_01_1  & 1)*1) >=11
 
}