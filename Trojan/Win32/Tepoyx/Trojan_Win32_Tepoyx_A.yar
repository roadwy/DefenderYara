
rule Trojan_Win32_Tepoyx_A{
	meta:
		description = "Trojan:Win32/Tepoyx.A,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {81 38 50 45 00 00 0f 85 ?? ?? ?? ?? 8d 50 78 8b 12 03 55 ?? 89 55 ?? 83 c0 78 8b 40 04 } //1
		$a_03_1 = {83 7e 04 05 72 0c 83 7e 04 05 75 0b 83 7e 08 00 75 05 e8 ?? ?? ?? ?? 83 7e 04 06 72 ?? c7 03 ff ff ff ff 68 ?? ?? ?? ?? 68 08 00 02 00 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}