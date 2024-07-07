
rule Trojan_Win32_Emotet_DAZ_MTB{
	meta:
		description = "Trojan:Win32/Emotet.DAZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {53 8b 5c 24 90 01 01 55 8b 6c 24 90 01 01 56 8b 74 24 90 01 01 8d 9b 00 00 00 00 8b c1 33 d2 f7 f3 83 c1 01 8a 44 55 00 30 44 31 ff 3b cf 75 90 00 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}