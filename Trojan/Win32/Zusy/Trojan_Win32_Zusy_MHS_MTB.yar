
rule Trojan_Win32_Zusy_MHS_MTB{
	meta:
		description = "Trojan:Win32/Zusy.MHS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 "
		
	strings :
		$a_01_0 = {b8 66 6f 72 74 b9 69 6e 65 74 33 06 33 4e 04 09 c1 } //2
		$a_01_1 = {6d 79 5f 6e 65 77 5f 68 6f 6f 6b 5f 70 72 6f 6a 65 63 74 2e 64 6c 6c } //1 my_new_hook_project.dll
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*1) >=3
 
}