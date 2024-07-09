
rule Trojan_Win32_EmotetCrypt_PDC_MTB{
	meta:
		description = "Trojan:Win32/EmotetCrypt.PDC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {0f b6 54 24 ?? a1 ?? ?? ?? ?? 8a 0c 02 8b 44 24 ?? 30 0c 28 45 83 c4 ?? 3b 6c 24 ?? 0f 8c } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}