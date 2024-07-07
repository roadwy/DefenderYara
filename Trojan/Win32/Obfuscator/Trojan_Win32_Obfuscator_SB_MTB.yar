
rule Trojan_Win32_Obfuscator_SB_MTB{
	meta:
		description = "Trojan:Win32/Obfuscator.SB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {89 8d 4c ff 90 01 02 8b 95 90 01 04 83 ca 19 8b 85 90 01 04 03 10 8b 8d 90 01 04 2b ca 89 8d 90 01 04 8b 95 90 01 04 8b 45 9c 8b 8d 90 01 04 89 0c 90 01 01 e9 90 00 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}