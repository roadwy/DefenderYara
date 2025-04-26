
rule Trojan_Win32_BlackMoon_GTS_MTB{
	meta:
		description = "Trojan:Win32/BlackMoon.GTS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0b 00 0b 00 02 00 00 "
		
	strings :
		$a_03_0 = {40 46 33 20 20 cd b7 d0 d8 c7 d0 bb ?? ?? ?? ?? 46 34 20 20 cf d4 ca be ?? ?? ?? ?? 20 20 00 20 20 20 41 49 } //10
		$a_01_1 = {42 6c 61 63 6b 4d 6f 6f 6e 20 52 75 6e 54 69 6d 65 20 45 72 72 6f 72 } //1 BlackMoon RunTime Error
	condition:
		((#a_03_0  & 1)*10+(#a_01_1  & 1)*1) >=11
 
}