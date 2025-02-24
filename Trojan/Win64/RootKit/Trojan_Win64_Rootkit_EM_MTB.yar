
rule Trojan_Win64_Rootkit_EM_MTB{
	meta:
		description = "Trojan:Win64/Rootkit.EM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_81_0 = {53 4f 46 54 57 41 52 45 5c 4d 61 73 6f 6e 63 6f 6e 66 69 67 } //1 SOFTWARE\Masonconfig
		$a_81_1 = {5c 5c 2e 5c 70 69 70 65 5c 4d 61 73 6f 6e 63 68 69 6c 64 70 72 6f 63 36 34 } //1 \\.\pipe\Masonchildproc64
		$a_81_2 = {5c 5c 2e 5c 70 69 70 65 5c 4d 61 73 6f 6e 63 68 69 6c 64 70 72 6f 63 33 32 } //1 \\.\pipe\Masonchildproc32
		$a_81_3 = {52 65 66 6c 65 63 74 69 76 65 44 6c 6c 4d 61 69 6e } //1 ReflectiveDllMain
		$a_81_4 = {2e 64 65 74 6f 75 72 } //1 .detour
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1) >=5
 
}