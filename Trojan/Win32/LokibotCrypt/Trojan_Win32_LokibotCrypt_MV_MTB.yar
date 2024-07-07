
rule Trojan_Win32_LokibotCrypt_MV_MTB{
	meta:
		description = "Trojan:Win32/LokibotCrypt.MV!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {8b 45 08 30 90 02 02 83 90 02 02 90 18 46 3b f7 90 18 a1 90 02 04 69 90 02 05 05 90 02 04 a3 90 02 04 0f 90 02 06 81 90 02 05 81 90 02 09 75 90 00 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}