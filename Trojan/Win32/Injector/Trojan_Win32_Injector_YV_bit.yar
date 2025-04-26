
rule Trojan_Win32_Injector_YV_bit{
	meta:
		description = "Trojan:Win32/Injector.YV!bit,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {88 54 0e ff 8b 35 ?? ?? ?? ?? 7c e7 90 09 0d 00 8b 15 ?? ?? ?? ?? 41 3b cf 8a 54 0a ff } //1
		$a_03_1 = {89 45 08 75 cd 90 09 2e 00 8b 35 ?? ?? ?? ?? 33 d2 8a 5c 0e ff f7 f7 49 8a 04 16 88 1c 16 8b 15 ?? ?? ?? ?? 88 04 0a c1 45 08 07 8b 45 08 2b c7 2d ?? ?? ?? ?? 85 c9 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}