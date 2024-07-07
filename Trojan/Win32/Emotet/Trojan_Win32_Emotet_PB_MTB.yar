
rule Trojan_Win32_Emotet_PB_MTB{
	meta:
		description = "Trojan:Win32/Emotet.PB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {03 45 f8 8b 88 c1 e0 ff ff 89 0d 90 01 03 00 90 02 50 8b 15 90 01 03 00 81 c2 c4 8e 60 01 89 15 90 01 03 00 a1 90 01 03 00 03 45 f8 8b 0d 90 01 03 00 89 88 c1 e0 ff ff 90 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}