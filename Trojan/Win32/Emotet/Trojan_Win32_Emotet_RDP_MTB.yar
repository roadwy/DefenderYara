
rule Trojan_Win32_Emotet_RDP_MTB{
	meta:
		description = "Trojan:Win32/Emotet.RDP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {81 c9 00 ff ff ff 41 8b 44 24 90 01 01 8a 4c 0c 90 01 01 8a 10 32 d1 88 10 40 89 44 24 90 01 01 8b 44 24 90 01 01 48 89 44 24 90 01 01 0f 85 90 00 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}