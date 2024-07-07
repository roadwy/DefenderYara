
rule Trojan_Win32_Zenpak_GPAC_MTB{
	meta:
		description = "Trojan:Win32/Zenpak.GPAC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 01 00 00 "
		
	strings :
		$a_01_0 = {32 1c 3e 8b 7d e8 88 1c 0f 8b 35 } //4
	condition:
		((#a_01_0  & 1)*4) >=4
 
}