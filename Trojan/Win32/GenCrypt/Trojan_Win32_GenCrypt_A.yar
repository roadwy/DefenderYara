
rule Trojan_Win32_GenCrypt_A{
	meta:
		description = "Trojan:Win32/GenCrypt.A,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {8b 45 c8 40 89 45 c8 6a 32 58 8b 4d c8 66 89 04 4d ?? ?? ?? ?? 8b 45 c8 40 89 45 c8 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}