
rule Trojan_Win32_Emotet_DHP_MTB{
	meta:
		description = "Trojan:Win32/Emotet.DHP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {33 c9 ff 45 f8 8a 55 90 01 01 8a 4d 90 01 01 c1 f9 90 01 01 c1 e2 90 01 01 0a d1 8b 4d f8 88 11 ff 45 f8 90 00 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}