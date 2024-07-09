
rule Trojan_Win32_Bunituicrypt_RT_MTB{
	meta:
		description = "Trojan:Win32/Bunituicrypt.RT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {8b d8 8b 45 ?? 8b 00 03 45 ?? 03 d8 e8 ?? ?? ?? ?? 2b ?? 8b 45 ?? 89 18 8b 45 ?? 03 45 ?? 2d 67 2b 00 00 03 45 ?? 8b 55 ?? 31 02 6a 00 e8 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}