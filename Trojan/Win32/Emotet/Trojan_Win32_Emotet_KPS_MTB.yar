
rule Trojan_Win32_Emotet_KPS_MTB{
	meta:
		description = "Trojan:Win32/Emotet.KPS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_02_0 = {0f be 04 39 8a c8 0a d8 8b 44 24 ?? 83 c4 3c f6 d1 0a d1 22 d3 88 17 } //2
		$a_02_1 = {0f be 04 0e 8a d3 8a c8 f6 d2 0a d8 8b 44 24 ?? f6 d1 0a d1 22 d3 88 14 2e } //2
	condition:
		((#a_02_0  & 1)*2+(#a_02_1  & 1)*2) >=2
 
}