
rule Backdoor_Win32_Farfli_VM_MTB{
	meta:
		description = "Backdoor:Win32/Farfli.VM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0c 00 0c 00 03 00 00 "
		
	strings :
		$a_02_0 = {8b 55 08 b8 ?? ?? ?? ?? 8a 0a 32 4d ef 02 4d ef 88 0a 42 89 55 08 c3 8b 45 e8 c7 45 ?? ?? ?? ?? ?? 40 eb bf } //10
		$a_80_1 = {32 33 34 35 4d 50 43 53 61 66 65 } //2345MPCSafe  1
		$a_01_2 = {56 69 72 74 75 61 6c 50 72 6f 74 65 63 74 } //1 VirtualProtect
	condition:
		((#a_02_0  & 1)*10+(#a_80_1  & 1)*1+(#a_01_2  & 1)*1) >=12
 
}