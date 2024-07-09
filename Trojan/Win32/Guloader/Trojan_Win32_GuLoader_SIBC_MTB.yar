
rule Trojan_Win32_GuLoader_SIBC_MTB{
	meta:
		description = "Trojan:Win32/GuLoader.SIBC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {8b 2c 17 66 [0-20] 90 18 [0-20] 90 18 [0-20] 81 f5 ?? ?? ?? ?? [0-20] 90 18 [0-20] 90 18 [0-20] 01 2c 16 [0-20] 90 18 [0-20] 90 18 [0-20] 90 18 83 da 04 0f 8d ?? ?? ?? ?? [0-20] 90 18 [0-20] 90 18 [0-20] ff e6 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}