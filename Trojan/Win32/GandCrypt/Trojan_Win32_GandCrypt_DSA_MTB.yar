
rule Trojan_Win32_GandCrypt_DSA_MTB{
	meta:
		description = "Trojan:Win32/GandCrypt.DSA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {8b 45 f0 03 45 e4 89 45 d8 8b 45 f0 c1 e8 05 89 45 f8 c7 05 ?? ?? ?? ?? 2e ce 50 91 8b 45 f8 03 45 cc 89 45 f8 81 3d ?? ?? ?? ?? 76 09 00 00 75 90 09 0a 00 c7 05 ?? ?? ?? ?? 40 2e eb ed } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}