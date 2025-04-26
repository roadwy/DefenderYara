
rule Trojan_Win32_AresLdrCrypt_PBA_MTB{
	meta:
		description = "Trojan:Win32/AresLdrCrypt.PBA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {8d 04 0a c1 f8 ?? 89 c2 89 c8 c1 f8 ?? 29 c2 89 d0 6b c0 ?? 29 c1 89 c8 89 c2 8b 45 ?? 01 d0 0f b6 00 31 f0 88 03 83 45 e4 01 } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}