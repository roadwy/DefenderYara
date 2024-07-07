
rule Trojan_Win32_Emotet_PVF_MTB{
	meta:
		description = "Trojan:Win32/Emotet.PVF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_02_0 = {0f b6 94 15 90 01 02 ff ff 8b 45 10 03 85 90 01 02 ff ff 0f b6 08 33 ca 8b 55 10 03 95 90 01 02 ff ff 88 0a 90 00 } //2
	condition:
		((#a_02_0  & 1)*2) >=2
 
}