
rule Trojan_Win32_Shelm_RR_MTB{
	meta:
		description = "Trojan:Win32/Shelm.RR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {88 8c 35 d4 fd ff ff 0f b6 c8 88 84 1d d4 fd ff ff 0f b6 84 35 d4 fd ff ff 03 c8 0f b6 c1 8b 8d e8 fe ff ff 0f b6 84 05 d4 fd ff ff 32 44 3a 08 88 04 11 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}