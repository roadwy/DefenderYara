
rule Trojan_Win32_Stealc_RD_MTB{
	meta:
		description = "Trojan:Win32/Stealc.RD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {0f b6 08 89 4d f8 8b 55 08 03 55 fc 0f b6 02 33 45 f4 8b 4d 08 03 4d fc 88 01 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}