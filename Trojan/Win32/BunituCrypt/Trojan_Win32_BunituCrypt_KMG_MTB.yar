
rule Trojan_Win32_BunituCrypt_KMG_MTB{
	meta:
		description = "Trojan:Win32/BunituCrypt.KMG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {c1 e8 05 89 45 90 01 01 8b 85 90 01 04 01 45 90 01 01 8b 85 90 01 04 03 f8 8b 85 90 01 04 03 c6 33 f8 31 7d 90 01 01 33 ff 81 3d 90 01 04 e6 06 00 00 c7 05 90 01 04 36 06 ea e9 75 90 00 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}