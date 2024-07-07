
rule Trojan_Win32_Nebuler_gen_I{
	meta:
		description = "Trojan:Win32/Nebuler.gen!I,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {8b 95 10 ff ff ff 3b 55 f4 73 37 6a 00 ff 15 90 01 04 89 45 f0 8b 45 08 03 85 10 ff ff ff 0f be 48 01 8b 95 10 ff ff ff 0f be 82 c0 24 01 10 33 c8 8b 95 0c ff ff ff 03 95 10 ff ff ff 88 0a eb 90 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}