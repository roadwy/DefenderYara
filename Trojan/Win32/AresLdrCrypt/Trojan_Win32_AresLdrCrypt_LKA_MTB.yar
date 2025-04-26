
rule Trojan_Win32_AresLdrCrypt_LKA_MTB{
	meta:
		description = "Trojan:Win32/AresLdrCrypt.LKA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {0f b6 00 31 f0 88 03 83 45 e4 01 8b 55 ?? ?? ?? ?? 39 c2 0f 82 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}