
rule Trojan_Win32_StopCrypt_RPT_MTB{
	meta:
		description = "Trojan:Win32/StopCrypt.RPT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {8b ce c1 e1 04 03 4d f0 8b c6 c1 e8 05 03 45 f4 8d 14 33 33 ca 33 c8 2b f9 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}