
rule Trojan_Win32_GhostRatCrypt_GA_MTB{
	meta:
		description = "Trojan:Win32/GhostRatCrypt.GA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_02_0 = {40 33 ff 89 45 90 01 01 57 8a 04 10 8a 14 0e 32 d0 88 14 0e ff 15 90 01 04 8b c6 b9 90 01 04 99 f7 f9 85 d2 90 00 } //10
	condition:
		((#a_02_0  & 1)*10) >=10
 
}