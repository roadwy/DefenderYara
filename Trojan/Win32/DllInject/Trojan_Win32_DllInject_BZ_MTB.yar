
rule Trojan_Win32_DllInject_BZ_MTB{
	meta:
		description = "Trojan:Win32/DllInject.BZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 03 00 00 "
		
	strings :
		$a_01_0 = {4a 69 61 6a 6f 69 66 6a 61 65 67 65 61 69 6a 67 64 6a } //3 Jiajoifjaegeaijgdj
		$a_01_1 = {4c 61 69 6f 66 67 6a 61 65 6f 69 67 65 61 67 68 } //3 Laiofgjaeoigeagh
		$a_01_2 = {57 61 69 74 46 6f 72 53 69 6e 67 6c 65 4f 62 6a 65 63 74 } //1 WaitForSingleObject
	condition:
		((#a_01_0  & 1)*3+(#a_01_1  & 1)*3+(#a_01_2  & 1)*1) >=7
 
}