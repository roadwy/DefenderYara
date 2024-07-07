
rule Trojan_Win32_Emotet_DBE_MTB{
	meta:
		description = "Trojan:Win32/Emotet.DBE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {6a 00 ff 15 90 01 04 33 d2 8b c6 f7 f3 8a 44 55 00 8a 14 3e 32 d0 8b 44 24 1c 88 14 3e 46 3b f0 75 90 00 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}