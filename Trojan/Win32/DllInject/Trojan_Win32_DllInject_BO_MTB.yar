
rule Trojan_Win32_DllInject_BO_MTB{
	meta:
		description = "Trojan:Win32/DllInject.BO!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 04 00 00 "
		
	strings :
		$a_01_0 = {54 63 72 4f 6e 62 } //2 TcrOnb
		$a_01_1 = {50 6a 6e 52 63 66 76 67 } //2 PjnRcfvg
		$a_01_2 = {52 76 67 62 68 54 68 62 6a } //2 RvgbhThbj
		$a_01_3 = {57 61 69 74 46 6f 72 53 69 6e 67 6c 65 4f 62 6a 65 63 74 } //1 WaitForSingleObject
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2+(#a_01_2  & 1)*2+(#a_01_3  & 1)*1) >=7
 
}