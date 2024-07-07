
rule Trojan_Win32_EmotetCrypt_PCU_MTB{
	meta:
		description = "Trojan:Win32/EmotetCrypt.PCU!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {0f b6 14 0e 0f b6 04 0f 03 c2 99 bb 90 01 04 f7 fb 45 0f b6 c2 8a 0c 08 8b 44 24 90 01 01 30 4c 28 ff 90 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}