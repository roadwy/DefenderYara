
rule Trojan_Win32_IcedID_M_MTB{
	meta:
		description = "Trojan:Win32/IcedID.M!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_02_0 = {6a 40 68 00 30 00 00 68 00 a0 01 00 6a 00 ff 15 ?? ?? ?? ?? 89 45 e4 68 00 a0 01 00 68 48 72 f3 05 } //1
		$a_00_1 = {6a 55 ba 02 00 00 00 6b c2 00 8b 4d fc 8d 54 01 04 52 6a 5c 68 00 04 00 00 ff 15 } //1
		$a_02_2 = {8b 4d fc 81 c1 b4 00 00 00 51 8b 55 fc 83 c2 04 52 51 f3 0f 10 05 ?? 34 f3 05 f3 0f 11 04 24 6a 05 6a 00 68 } //1
	condition:
		((#a_02_0  & 1)*1+(#a_00_1  & 1)*1+(#a_02_2  & 1)*1) >=3
 
}