
rule Trojan_Win32_Emotet_DDQ_MTB{
	meta:
		description = "Trojan:Win32/Emotet.DDQ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {57 57 8d 4c 24 1c 51 57 6a 01 50 56 ff d5 85 c0 74 [0-07] e8 ?? ?? ?? ?? 8b 54 24 14 83 c4 04 57 57 8d 4c 24 1c 51 50 6a 01 52 56 89 44 24 54 ff d5 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}