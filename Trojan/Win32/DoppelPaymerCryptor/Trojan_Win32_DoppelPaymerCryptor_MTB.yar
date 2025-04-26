
rule Trojan_Win32_DoppelPaymerCryptor_MTB{
	meta:
		description = "Trojan:Win32/DoppelPaymerCryptor!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {8b 45 e4 b9 ?? ?? ?? ?? 2b 4d f4 8b 55 ec 8a 1c 02 8b 75 e8 88 1c 06 01 c8 8b 4d f0 39 c8 89 45 e4 74 ?? eb ?? 31 c0 89 45 e4 eb } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}