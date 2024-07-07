
rule Trojan_Win32_Emotet_PDK_MTB{
	meta:
		description = "Trojan:Win32/Emotet.PDK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {0f b6 cb 03 c1 99 b9 90 01 04 f7 f9 8a 5d 90 01 01 8d 4c 24 90 01 01 8a 94 14 90 01 04 32 da 88 5d 90 00 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}