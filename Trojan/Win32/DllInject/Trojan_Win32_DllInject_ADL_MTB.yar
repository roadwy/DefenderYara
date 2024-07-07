
rule Trojan_Win32_DllInject_ADL_MTB{
	meta:
		description = "Trojan:Win32/DllInject.ADL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {ad a6 a4 00 8b 90 01 04 70 70 00 69 5f 5a 00 5b 4e 46 00 55 45 3a 00 53 42 35 90 01 04 00 50 3f 35 00 4f 41 34 00 50 42 34 00 51 43 35 90 01 04 00 54 46 38 00 57 49 3b 00 5d 4e 42 00 60 53 47 00 64 56 4c 00 68 5d 55 00 6d 63 5b 00 71 68 90 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}