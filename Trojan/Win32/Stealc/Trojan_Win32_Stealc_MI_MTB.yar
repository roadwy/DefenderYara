
rule Trojan_Win32_Stealc_MI_MTB{
	meta:
		description = "Trojan:Win32/Stealc.MI!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {b8 31 a2 00 00 01 85 5c ef ff ff a1 90 01 04 03 85 60 ef ff ff 8b 8d 5c ef ff ff 03 8d 60 ef ff ff 8a 09 88 08 81 3d 90 01 04 ab 05 00 00 90 00 } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}