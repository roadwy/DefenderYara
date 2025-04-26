
rule Trojan_Win32_Tedy_RV_MTB{
	meta:
		description = "Trojan:Win32/Tedy.RV!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 02 00 00 "
		
	strings :
		$a_01_0 = {69 8d 94 ef ff ff fe 00 00 00 81 c1 3b 66 f3 56 69 95 94 ef ff ff fe 00 00 00 2b ca 33 8d ac e1 ff ff 0f af 8d 94 ef ff ff 69 85 94 ef ff ff fe 00 00 00 2b c8 89 8d 90 ef ff ff } //5
		$a_01_1 = {5c 6f 75 74 70 75 74 5c 47 32 4d 5f 44 6c 6c 2e 70 64 62 } //1 \output\G2M_Dll.pdb
	condition:
		((#a_01_0  & 1)*5+(#a_01_1  & 1)*1) >=6
 
}