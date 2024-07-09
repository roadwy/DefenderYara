
rule Trojan_Win32_VBkrypt_GD_MTB{
	meta:
		description = "Trojan:Win32/VBkrypt.GD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {83 f9 00 7d [0-19] ff d0 90 0a 64 00 8b 14 0f [0-28] 31 f2 [0-0a] 09 14 08 [0-19] 83 e9 04 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}