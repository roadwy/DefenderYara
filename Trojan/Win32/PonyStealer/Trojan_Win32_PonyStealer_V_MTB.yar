
rule Trojan_Win32_PonyStealer_V_MTB{
	meta:
		description = "Trojan:Win32/PonyStealer.V!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_02_0 = {6a 00 ff 15 90 01 04 a1 90 01 04 50 ba 90 01 04 e8 90 01 04 0f b7 05 90 01 04 25 90 01 04 c3 90 00 } //1
		$a_02_1 = {0f af 44 24 90 01 01 c7 04 24 90 01 04 81 04 24 90 01 04 8b 0c 24 03 c8 89 0a 59 c2 90 09 06 00 51 e8 90 00 } //1
		$a_00_2 = {e8 67 ff ff ff 30 06 c3 } //1
	condition:
		((#a_02_0  & 1)*1+(#a_02_1  & 1)*1+(#a_00_2  & 1)*1) >=3
 
}