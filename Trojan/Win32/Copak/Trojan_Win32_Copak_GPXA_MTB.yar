
rule Trojan_Win32_Copak_GPXA_MTB{
	meta:
		description = "Trojan:Win32/Copak.GPXA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 02 00 00 "
		
	strings :
		$a_03_0 = {96 87 a7 00 [0-30] 8a 89 a7 00 [0-30] 81 ?? ff 00 00 00 [0-30] 31 [0-70] 0f } //4
		$a_81_1 = {56 69 72 74 75 61 6c 50 72 6f 74 65 63 74 } //1 VirtualProtect
	condition:
		((#a_03_0  & 1)*4+(#a_81_1  & 1)*1) >=5
 
}