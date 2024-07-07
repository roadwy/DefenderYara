
rule Trojan_Win32_Farfli_TI_MTB{
	meta:
		description = "Trojan:Win32/Farfli.TI!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {8a 08 32 ca 02 ca 88 08 40 4e 75 f4 } //1
		$a_01_1 = {56 69 72 74 75 61 6c 50 72 6f 74 65 63 74 } //1 VirtualProtect
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}