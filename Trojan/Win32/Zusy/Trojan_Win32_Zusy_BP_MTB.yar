
rule Trojan_Win32_Zusy_BP_MTB{
	meta:
		description = "Trojan:Win32/Zusy.BP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 04 00 00 "
		
	strings :
		$a_01_0 = {42 73 69 73 65 72 68 6a 41 69 73 72 6a 6f 68 6a 72 69 68 } //2 BsiserhjAisrjohjrih
		$a_01_1 = {48 73 72 6a 69 73 72 6a 41 6a 73 72 69 68 6a 72 } //2 HsrjisrjAjsrihjr
		$a_01_2 = {4f 73 6a 69 67 6a 73 72 41 6a 69 65 6a 67 69 65 73 6a } //2 OsjigjsrAjiejgiesj
		$a_01_3 = {57 61 69 74 46 6f 72 53 69 6e 67 6c 65 4f 62 6a 65 63 74 } //1 WaitForSingleObject
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2+(#a_01_2  & 1)*2+(#a_01_3  & 1)*1) >=7
 
}