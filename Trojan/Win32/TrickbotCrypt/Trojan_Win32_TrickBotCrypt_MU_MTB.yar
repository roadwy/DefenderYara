
rule Trojan_Win32_TrickBotCrypt_MU_MTB{
	meta:
		description = "Trojan:Win32/TrickBotCrypt.MU!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {0f b6 06 46 90 02 04 51 50 c7 90 02 06 59 bb 90 02 04 89 90 02 02 33 90 02 07 31 90 01 01 8b 90 02 02 c7 90 02 06 d3 90 01 01 8a 90 01 01 8a 90 01 01 d3 90 01 01 ff 90 02 02 75 90 01 01 59 53 8f 90 02 02 ff 90 02 02 58 aa 49 75 90 00 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}