
rule Trojan_Win32_Emotet_DDJ_MTB{
	meta:
		description = "Trojan:Win32/Emotet.DDJ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {8a d0 89 4c 24 90 01 01 f6 d2 f6 d1 0a d1 8a 4c 24 90 1b 00 0a c1 22 d0 8b 44 24 90 01 01 88 10 90 00 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}