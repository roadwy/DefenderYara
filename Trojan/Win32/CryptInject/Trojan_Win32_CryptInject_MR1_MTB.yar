
rule Trojan_Win32_CryptInject_MR1_MTB{
	meta:
		description = "Trojan:Win32/CryptInject.MR1!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {8b 75 c0 33 d2 8b 45 ?? 89 5d ?? 8a 0c 06 8b c6 f7 75 ?? 8b 45 ?? 88 4d ?? 8a 04 02 32 c1 8b 4d ?? 88 04 0e } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}