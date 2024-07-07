
rule Trojan_Win32_Emotet_YA_MTB{
	meta:
		description = "Trojan:Win32/Emotet.YA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {55 8b ec 57 eb 00 a1 90 01 03 00 a3 90 01 03 00 8b 90 01 04 00 8b 11 89 90 01 04 00 a1 90 01 03 00 83 90 01 02 a3 90 01 03 00 8b 90 01 04 00 83 90 01 02 a1 90 01 03 00 8b ff 8b ca a3 90 01 03 00 eb 01 c3 90 00 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}