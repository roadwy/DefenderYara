
rule Trojan_Win32_Tedy_GPA_MTB{
	meta:
		description = "Trojan:Win32/Tedy.GPA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 02 00 00 "
		
	strings :
		$a_03_0 = {0f 1f 00 8a 88 ?? ?? ?? ?? 80 f1 ?? 88 8c 05 ?? ?? ff ff 40 3d } //3
		$a_81_1 = {43 72 65 61 74 65 54 6f 6f 6c 68 65 6c 70 33 32 53 6e 61 70 73 68 6f 74 } //3 CreateToolhelp32Snapshot
	condition:
		((#a_03_0  & 1)*3+(#a_81_1  & 1)*3) >=6
 
}