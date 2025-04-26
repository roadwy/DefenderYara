
rule Trojan_Win32_Swisyn_MBXR_MTB{
	meta:
		description = "Trojan:Win32/Swisyn.MBXR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {6c 35 40 00 01 f8 30 00 00 ff ff ff 08 00 00 00 01 00 00 00 01 00 00 00 e9 00 00 00 64 32 40 00 68 31 40 00 fc 2b 40 00 78 00 00 00 83 00 00 00 87 00 00 00 88 } //1
		$a_01_1 = {4b 4c 70 72 6f 6a 4d 61 69 6e } //1 KLprojMain
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}