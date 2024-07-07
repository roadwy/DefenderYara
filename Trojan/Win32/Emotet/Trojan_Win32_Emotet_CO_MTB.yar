
rule Trojan_Win32_Emotet_CO_MTB{
	meta:
		description = "Trojan:Win32/Emotet.CO!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {6a 64 6a 64 6a 64 6a 64 6a 64 68 90 01 04 e8 90 01 04 dd 05 90 01 04 83 c4 24 dd 54 24 10 dd 54 24 08 dd 1c 24 68 90 01 04 e8 90 01 04 02 5c 24 6c 8b 44 24 70 0f b6 cb 8a 54 0c 74 30 14 30 83 c4 1c 83 c6 01 3b 75 0c 0f 8c 90 00 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}