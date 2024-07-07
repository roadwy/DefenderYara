
rule Trojan_Win32_Emotet_PVG_MTB{
	meta:
		description = "Trojan:Win32/Emotet.PVG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_02_0 = {0f b6 44 34 1c 0f b6 cb 03 c1 99 b9 90 01 04 f7 f9 83 c5 01 8a 54 14 1c 30 55 ff 90 00 } //2
	condition:
		((#a_02_0  & 1)*2) >=2
 
}