
rule Trojan_Win32_Neoreblamy_SPSH_MTB{
	meta:
		description = "Trojan:Win32/Neoreblamy.SPSH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 04 00 00 "
		
	strings :
		$a_01_0 = {42 6a 73 64 4b 7a 70 6d 75 5a 7a 4b 72 6f 4b } //2 BjsdKzpmuZzKroK
		$a_01_1 = {4c 75 46 4f 71 7a 79 69 58 4f 70 65 50 6b 43 74 78 68 65 6b 47 46 43 57 75 } //1 LuFOqzyiXOpePkCtxhekGFCWu
		$a_01_2 = {56 63 77 63 4f 5a 46 53 77 6f 52 42 5a 67 75 74 6e 79 73 61 } //1 VcwcOZFSwoRBZgutnysa
		$a_01_3 = {4a 58 43 4c 6e 41 50 71 53 4f 4f 5a 71 41 78 51 5a 6b 70 7a } //1 JXCLnAPqSOOZqAxQZkpz
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=5
 
}