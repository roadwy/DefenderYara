
rule Trojan_Win32_Emotet_PW_MTB{
	meta:
		description = "Trojan:Win32/Emotet.PW!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {b8 18 66 03 10 c3 b8 20 66 03 10 c3 e8 90 02 04 8b 48 90 01 01 83 08 90 01 01 89 48 90 01 01 e8 90 02 04 8b 48 90 01 01 83 08 02 89 48 90 01 01 c3 b8 d8 6c 03 10 c3 90 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}