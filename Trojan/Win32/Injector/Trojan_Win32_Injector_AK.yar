
rule Trojan_Win32_Injector_AK{
	meta:
		description = "Trojan:Win32/Injector.AK,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_02_0 = {8d 70 01 8a 08 40 3a cb 75 f9 2b c6 50 57 8d 4c 24 28 e8 ?? ?? ?? ?? c6 44 24 60 02 } //1
		$a_02_1 = {83 c4 0c 8d 4c 24 18 51 68 03 01 00 00 ff d0 85 c0 74 ?? 8b 0d ?? ?? ?? ?? 33 c0 c6 ?? ?? ?? 00 } //1
	condition:
		((#a_02_0  & 1)*1+(#a_02_1  & 1)*1) >=2
 
}