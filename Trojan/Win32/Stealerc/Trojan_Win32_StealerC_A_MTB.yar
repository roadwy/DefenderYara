
rule Trojan_Win32_StealerC_A_MTB{
	meta:
		description = "Trojan:Win32/StealerC.A!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_03_0 = {8b 55 08 03 55 fc 0f b6 02 35 ?? 00 00 00 8b 4d 08 03 4d fc 88 01 } //1
		$a_01_1 = {75 42 73 79 68 62 78 55 41 4e 6e 69 77 75 } //1 uBsyhbxUANniwu
		$a_01_2 = {44 53 75 79 67 61 63 } //1 DSuygac
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}