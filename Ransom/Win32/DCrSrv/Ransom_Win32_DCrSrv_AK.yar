
rule Ransom_Win32_DCrSrv_AK{
	meta:
		description = "Ransom:Win32/DCrSrv.AK,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 03 00 00 "
		
	strings :
		$a_81_0 = {44 43 72 53 72 76 5c 52 65 6c 65 61 73 65 5c 44 43 72 53 72 76 2e 70 64 62 } //5 DCrSrv\Release\DCrSrv.pdb
		$a_81_1 = {44 43 6d 6f 64 5c 44 69 73 6b 43 72 79 70 74 6f 72 5c 44 43 72 79 70 74 5c 42 69 6e 5c 62 6f 6f 74 5c 62 6f 6f 74 5f 68 6f 6f 6b 5f 73 6d 61 6c 6c 2e 70 64 62 } //1 DCmod\DiskCryptor\DCrypt\Bin\boot\boot_hook_small.pdb
		$a_81_2 = {44 43 6d 6f 64 5c 44 69 73 6b 43 72 79 70 74 6f 72 5c 44 43 72 79 70 74 5c 42 69 6e 5c 62 6f 6f 74 5c 62 6f 6f 74 5f 6c 6f 61 64 2e 70 64 62 } //1 DCmod\DiskCryptor\DCrypt\Bin\boot\boot_load.pdb
	condition:
		((#a_81_0  & 1)*5+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1) >=6
 
}