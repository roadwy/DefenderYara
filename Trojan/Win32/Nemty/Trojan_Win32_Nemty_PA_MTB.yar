
rule Trojan_Win32_Nemty_PA_MTB{
	meta:
		description = "Trojan:Win32/Nemty.PA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 02 00 00 "
		
	strings :
		$a_02_0 = {f5 11 00 00 75 0e 6a 00 ff 15 90 01 04 8b 0d 90 01 04 69 c9 90 01 04 81 c1 90 01 04 8b c1 89 0d 90 01 04 c1 e8 10 30 04 90 01 02 3b 90 01 01 7c cb 90 09 02 00 81 90 00 } //4
		$a_01_1 = {56 69 72 74 75 61 6c 50 72 6f 74 65 63 74 } //1 VirtualProtect
	condition:
		((#a_02_0  & 1)*4+(#a_01_1  & 1)*1) >=5
 
}