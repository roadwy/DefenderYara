
rule Trojan_Win32_Emotet_DHY_MTB{
	meta:
		description = "Trojan:Win32/Emotet.DHY!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_02_0 = {8b 5c b0 08 89 5c 88 08 89 54 b0 08 03 da 81 e3 ?? ?? ?? ?? 0f b6 54 98 08 32 55 00 41 88 17 81 e1 90 1b 00 8b 54 88 08 03 f2 81 e6 ff 00 00 00 } //1
		$a_00_1 = {c1 c8 0d 80 f9 61 0f b6 c9 72 03 83 e9 20 42 03 c1 8a 0a 84 c9 75 e9 } //1
	condition:
		((#a_02_0  & 1)*1+(#a_00_1  & 1)*1) >=2
 
}