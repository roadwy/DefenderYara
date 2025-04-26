
rule Trojan_Win32_PonyStealer_DAB_MTB{
	meta:
		description = "Trojan:Win32/PonyStealer.DAB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 01 00 00 "
		
	strings :
		$a_01_0 = {0f b6 06 30 d8 f6 d0 46 04 62 c0 c0 04 04 8b 30 c3 66 59 88 0c 07 e9 } //4
	condition:
		((#a_01_0  & 1)*4) >=4
 
}