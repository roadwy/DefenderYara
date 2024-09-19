
rule Trojan_Win32_Dridex_PAC_MTB{
	meta:
		description = "Trojan:Win32/Dridex.PAC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_80_0 = {63 3a 5c 74 72 79 5c 46 61 69 72 5c 44 69 64 2d 6d 69 73 73 5c 4e 65 69 67 68 5c 44 65 65 70 2e 70 64 62 } //c:\try\Fair\Did-miss\Neigh\Deep.pdb  1
		$a_80_1 = {44 65 65 70 2e 64 6c 6c } //Deep.dll  1
		$a_00_2 = {8b 0d 04 a0 05 01 56 57 bf 4e e6 40 bb be 00 00 ff ff 3b cf 74 04 85 ce 75 26 } //1
	condition:
		((#a_80_0  & 1)*1+(#a_80_1  & 1)*1+(#a_00_2  & 1)*1) >=3
 
}