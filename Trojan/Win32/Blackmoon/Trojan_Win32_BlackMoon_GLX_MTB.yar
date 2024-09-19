
rule Trojan_Win32_BlackMoon_GLX_MTB{
	meta:
		description = "Trojan:Win32/BlackMoon.GLX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0c 00 0c 00 03 00 00 "
		
	strings :
		$a_03_0 = {47 00 da af 47 00 87 ?? ?? ?? ?? b0 47 00 27 b2 47 00 b8 ?? ?? ?? ?? b4 47 00 5f b4 47 } //10
		$a_01_1 = {42 63 6e 54 70 31 68 30 64 6e 4d 46 64 4c 6c 6d } //1 BcnTp1h0dnMFdLlm
		$a_01_2 = {42 6c 61 63 6b 4d 6f 6f 6e 20 52 75 6e 54 69 6d 65 } //1 BlackMoon RunTime
	condition:
		((#a_03_0  & 1)*10+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=12
 
}