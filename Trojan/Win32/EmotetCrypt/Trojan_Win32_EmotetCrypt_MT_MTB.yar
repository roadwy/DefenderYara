
rule Trojan_Win32_EmotetCrypt_MT_MTB{
	meta:
		description = "Trojan:Win32/EmotetCrypt.MT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {8b f0 d3 e0 c1 ee 05 03 74 24 38 03 44 24 2c 89 74 24 10 8b c8 e8 90 01 04 33 c6 89 44 24 24 89 2d 90 01 04 8b 44 24 24 29 44 24 14 81 3d 90 01 08 75 90 00 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}