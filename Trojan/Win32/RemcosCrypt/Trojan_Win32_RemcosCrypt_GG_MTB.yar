
rule Trojan_Win32_RemcosCrypt_GG_MTB{
	meta:
		description = "Trojan:Win32/RemcosCrypt.GG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {8b 04 99 8b 55 ?? 8b 4d ?? 33 04 8a 8b 55 ?? 8b 4d ?? 89 04 8a 66 a1 [0-04] 66 3b 05 90 0a 3c 00 8b 15 [0-04] 33 15 [0-04] 3b 15 [0-04] 8b 4d ?? 8b 5d } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}