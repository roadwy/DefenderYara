
rule Trojan_Win32_BlackMoon_GTK_MTB{
	meta:
		description = "Trojan:Win32/BlackMoon.GTK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0b 00 0b 00 03 00 00 "
		
	strings :
		$a_01_0 = {0a 04 03 02 03 07 10 09 18 0a 02 06 } //5
		$a_03_1 = {02 03 0a 9f ?? ?? ?? ?? 04 07 03 2b 0a 03 82 36 } //5
		$a_01_2 = {42 6c 61 63 6b 4d 6f 6f 6e 20 52 75 6e 54 69 6d 65 20 45 72 72 6f 72 } //1 BlackMoon RunTime Error
	condition:
		((#a_01_0  & 1)*5+(#a_03_1  & 1)*5+(#a_01_2  & 1)*1) >=11
 
}