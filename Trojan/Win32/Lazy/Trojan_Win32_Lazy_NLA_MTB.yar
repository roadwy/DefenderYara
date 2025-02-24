
rule Trojan_Win32_Lazy_NLA_MTB{
	meta:
		description = "Trojan:Win32/Lazy.NLA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 04 00 00 "
		
	strings :
		$a_03_0 = {ff 66 81 3f ?? 00 0f 94 c7 20 fb f6 c3 01 89 85 84 fd ff ff } //2
		$a_03_1 = {8b 8d 88 fd ff ff 66 81 39 ?? 00 0f 94 c3 } //1
		$a_03_2 = {8b 95 8c fd ff ff 66 81 3a ?? 00 0f 94 c7 } //1
		$a_81_3 = {5c 6c 6f 61 64 65 72 2e 63 70 70 2e 62 63 2e 6f 62 6a 2e 70 64 62 } //1 \loader.cpp.bc.obj.pdb
	condition:
		((#a_03_0  & 1)*2+(#a_03_1  & 1)*1+(#a_03_2  & 1)*1+(#a_81_3  & 1)*1) >=5
 
}