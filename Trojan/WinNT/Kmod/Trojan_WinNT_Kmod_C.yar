
rule Trojan_WinNT_Kmod_C{
	meta:
		description = "Trojan:WinNT/Kmod.C,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_00_0 = {fa 0f 20 c0 25 ff ff fe ff 0f 22 c0 8b 03 89 04 91 0f 20 c0 0d 00 00 01 00 0f 22 c0 fb } //1
		$a_02_1 = {83 4d fc ff 8b 45 e0 8b 10 a1 90 01 04 39 50 08 77 90 01 01 c7 45 e4 0d 00 00 c0 90 00 } //1
		$a_00_2 = {4b 65 53 65 72 76 69 63 65 44 65 73 63 72 69 70 74 6f 72 54 61 62 6c 65 } //1 KeServiceDescriptorTable
	condition:
		((#a_00_0  & 1)*1+(#a_02_1  & 1)*1+(#a_00_2  & 1)*1) >=3
 
}