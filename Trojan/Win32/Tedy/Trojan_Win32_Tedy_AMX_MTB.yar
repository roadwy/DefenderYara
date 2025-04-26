
rule Trojan_Win32_Tedy_AMX_MTB{
	meta:
		description = "Trojan:Win32/Tedy.AMX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 02 00 00 "
		
	strings :
		$a_01_0 = {f6 17 d9 ff d9 fe 90 90 89 c0 80 2f 45 80 2f 29 d9 ff d9 fe 90 90 89 c0 47 e2 } //4
		$a_80_1 = {57 69 6e 64 6f 77 73 48 61 6e 64 6c 65 } //WindowsHandle  1
	condition:
		((#a_01_0  & 1)*4+(#a_80_1  & 1)*1) >=5
 
}