
rule Trojan_Win32_Emotet_DCX_MTB{
	meta:
		description = "Trojan:Win32/Emotet.DCX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {57 ff d6 8a 03 0f b6 4d 90 01 01 88 45 90 01 01 0f b6 c0 03 c1 b9 90 01 04 99 f7 f9 8b 45 f4 8a 8c 15 90 01 04 30 08 90 02 03 ff 4d f0 89 45 f4 0f 85 90 00 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}