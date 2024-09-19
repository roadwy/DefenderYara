
rule Trojan_Win32_StealC_WS_MTB{
	meta:
		description = "Trojan:Win32/StealC.WS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {8a 85 f8 fb ff ff 30 04 3b 83 7d 08 0f 59 75 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}