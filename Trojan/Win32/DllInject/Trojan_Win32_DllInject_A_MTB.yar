
rule Trojan_Win32_DllInject_A_MTB{
	meta:
		description = "Trojan:Win32/DllInject.A!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 01 00 00 "
		
	strings :
		$a_03_0 = {15 10 ff 15 00 ?? 11 10 6a 00 6a 00 6a 01 68 ?? ?? 15 10 ff 15 04 ?? 11 10 c7 05 ?? ?? 15 10 0c 00 00 00 c7 05 } //7
	condition:
		((#a_03_0  & 1)*7) >=7
 
}
rule Trojan_Win32_DllInject_A_MTB_2{
	meta:
		description = "Trojan:Win32/DllInject.A!MTB,SIGNATURE_TYPE_PEHSTR,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {8b 45 08 03 45 f4 0f b6 08 8b 45 f4 99 be 1c 00 00 00 f7 fe 8b 45 fc 0f b6 14 10 33 ca 8b 45 f8 03 45 f4 88 08 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}