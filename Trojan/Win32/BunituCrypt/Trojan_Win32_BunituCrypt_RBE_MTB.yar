
rule Trojan_Win32_BunituCrypt_RBE_MTB{
	meta:
		description = "Trojan:Win32/BunituCrypt.RBE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {68 3b 11 00 00 6a 00 e8 90 01 04 03 d8 8b 45 90 01 01 31 18 83 45 90 01 01 04 83 45 90 01 01 04 8b 45 90 01 01 3b 45 90 01 01 72 90 00 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}