
rule Trojan_Win32_DllInject_BT_MTB{
	meta:
		description = "Trojan:Win32/DllInject.BT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 03 00 00 "
		
	strings :
		$a_01_0 = {43 6f 6b 67 73 6f 69 67 6a 73 65 6f 69 67 6a 73 65 } //3 Cokgsoigjseoigjse
		$a_01_1 = {48 6f 69 73 64 67 6a 66 69 6f 73 6a 67 69 65 } //3 Hoisdgjfiosjgie
		$a_01_2 = {57 61 69 74 46 6f 72 53 69 6e 67 6c 65 4f 62 6a 65 63 74 } //1 WaitForSingleObject
	condition:
		((#a_01_0  & 1)*3+(#a_01_1  & 1)*3+(#a_01_2  & 1)*1) >=7
 
}