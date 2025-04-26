
rule Trojan_Win32_Fauppod_MF_MTB{
	meta:
		description = "Trojan:Win32/Fauppod.MF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 04 00 00 "
		
	strings :
		$a_01_0 = {4f 6e 65 4e 64 6f 50 72 6f } //2 OneNdoPro
		$a_01_1 = {54 77 6f 4e 64 6f 50 72 6f } //2 TwoNdoPro
		$a_01_2 = {54 68 72 4e 64 6f 50 72 6f } //2 ThrNdoPro
		$a_01_3 = {57 61 69 74 46 6f 72 53 69 6e 67 6c 65 4f 62 6a 65 63 74 } //1 WaitForSingleObject
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2+(#a_01_2  & 1)*2+(#a_01_3  & 1)*1) >=7
 
}