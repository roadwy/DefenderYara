
rule Trojan_Win32_BlackMoon_GTC_MTB{
	meta:
		description = "Trojan:Win32/BlackMoon.GTC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0b 00 0b 00 03 00 00 "
		
	strings :
		$a_03_0 = {84 03 00 0c 85 ?? ?? ?? ?? 03 00 34 85 03 00 30 89 03 00 b6 83 } //5
		$a_03_1 = {3e 8a 03 00 50 ?? 03 00 58 8a 03 00 66 ?? 03 00 } //5
		$a_01_2 = {42 6c 61 63 6b 4d 6f 6f 6e 20 52 75 6e 54 69 6d 65 20 45 72 72 6f 72 } //1 BlackMoon RunTime Error
	condition:
		((#a_03_0  & 1)*5+(#a_03_1  & 1)*5+(#a_01_2  & 1)*1) >=11
 
}