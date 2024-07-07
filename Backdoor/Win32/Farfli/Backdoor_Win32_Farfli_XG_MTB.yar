
rule Backdoor_Win32_Farfli_XG_MTB{
	meta:
		description = "Backdoor:Win32/Farfli.XG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {2f 2f 67 69 74 65 65 2e 63 6f 6d } //1 //gitee.com
		$a_01_1 = {2f 2f 50 72 6f 67 72 61 6d 44 61 74 61 2f 2f 53 65 6e 2e 70 6e 67 } //1 //ProgramData//Sen.png
		$a_01_2 = {56 69 72 74 75 61 6c 50 72 6f 74 65 63 74 } //1 VirtualProtect
		$a_01_3 = {56 69 72 74 75 61 6c 41 6c 6c 6f 63 } //1 VirtualAlloc
		$a_01_4 = {68 6c 6f 77 6f 72 6c 64 2e 63 6e } //1 hloworld.cn
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}