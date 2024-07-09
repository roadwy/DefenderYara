
rule Trojan_Win32_VidarCrypt_PAD_MTB{
	meta:
		description = "Trojan:Win32/VidarCrypt.PAD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {8b cf c1 e9 ?? 03 4d ec 03 c2 33 c8 8d 04 3b 33 c8 } //1
		$a_03_1 = {2b f1 8b ce c1 e1 ?? 03 4d f0 8b c6 c1 e8 ?? 03 45 f4 8d 14 33 33 ca 33 c8 2b f9 81 3d } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}