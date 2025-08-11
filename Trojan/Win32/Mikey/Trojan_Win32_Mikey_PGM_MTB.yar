
rule Trojan_Win32_Mikey_PGM_MTB{
	meta:
		description = "Trojan:Win32/Mikey.PGM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {51 6a 01 68 c8 71 40 00 56 ?? ?? d0 ab 40 00 6a 00 8d 95 ec ec ff ff 52 6a 01 68 bc 71 40 00 56 ?? ?? d0 ab 40 00 6a 00 8d 85 ec ec ff ff 50 6a 01 68 b8 71 40 00 56 } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}