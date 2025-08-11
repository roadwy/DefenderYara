
rule Trojan_Win32_Neoreblamy_NJS_MTB{
	meta:
		description = "Trojan:Win32/Neoreblamy.NJS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 "
		
	strings :
		$a_01_0 = {8b 45 94 40 89 45 94 83 7d 94 03 7d 10 8b 45 94 } //1
		$a_03_1 = {33 c0 40 6b c0 00 0f b6 84 05 ?? ff ff ff 8d 44 00 02 39 45 d8 } //2
	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*2) >=3
 
}