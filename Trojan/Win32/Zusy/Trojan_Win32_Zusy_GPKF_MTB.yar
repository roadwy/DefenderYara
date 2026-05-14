
rule Trojan_Win32_Zusy_GPKF_MTB{
	meta:
		description = "Trojan:Win32/Zusy.GPKF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 02 00 00 "
		
	strings :
		$a_01_0 = {30 18 40 80 38 00 75 f8 } //5
		$a_01_1 = {5f 52 65 66 6c 65 63 74 69 76 65 4c 6f 61 64 65 72 40 34 } //2 _ReflectiveLoader@4
	condition:
		((#a_01_0  & 1)*5+(#a_01_1  & 1)*2) >=7
 
}