
rule Backdoor_Win32_Farfli_VM_MTB{
	meta:
		description = "Backdoor:Win32/Farfli.VM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0c 00 0c 00 03 00 00 0a 00 "
		
	strings :
		$a_02_0 = {8b 55 08 b8 90 01 04 8a 0a 32 4d ef 02 4d ef 88 0a 42 89 55 08 c3 8b 45 e8 c7 45 90 01 05 40 eb bf 90 00 } //01 00 
		$a_80_1 = {32 33 34 35 4d 50 43 53 61 66 65 } //2345MPCSafe  01 00 
		$a_01_2 = {56 69 72 74 75 61 6c 50 72 6f 74 65 63 74 } //00 00  VirtualProtect
	condition:
		any of ($a_*)
 
}