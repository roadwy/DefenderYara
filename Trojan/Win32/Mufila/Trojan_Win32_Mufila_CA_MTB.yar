
rule Trojan_Win32_Mufila_CA_MTB{
	meta:
		description = "Trojan:Win32/Mufila.CA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_00_0 = {8b 55 fc 32 04 16 88 06 83 f9 0d 72 d7 } //1
		$a_81_1 = {76 6d 63 68 65 63 6b 2e 64 6c 6c } //1 vmcheck.dll
		$a_81_2 = {61 70 69 5f 6c 6f 67 2e 64 6c 6c } //1 api_log.dll
		$a_01_3 = {56 69 72 74 75 61 6c 50 72 6f 74 65 63 74 } //1 VirtualProtect
	condition:
		((#a_00_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}