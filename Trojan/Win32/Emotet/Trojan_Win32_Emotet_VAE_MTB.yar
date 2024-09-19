
rule Trojan_Win32_Emotet_VAE_MTB{
	meta:
		description = "Trojan:Win32/Emotet.VAE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {0f b6 ca 8b 54 24 08 01 d1 21 f1 8b 74 24 24 8a 0c 0e 8b 54 24 ?? 8b 74 24 2c 32 0c 16 8b 54 24 70 8b 74 24 28 88 0c 16 03 7c 24 70 89 5c 24 4c 89 7c 24 6c } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}