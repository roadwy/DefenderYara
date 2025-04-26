
rule Ransom_Win32_Morpheus_DA_MTB{
	meta:
		description = "Ransom:Win32/Morpheus.DA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0d 00 0d 00 04 00 00 "
		
	strings :
		$a_80_0 = {59 6f 75 72 20 6e 65 74 77 6f 72 6b 20 68 61 73 20 62 65 65 6e 20 62 72 65 61 63 68 65 64 20 61 6e 64 20 61 6c 6c 20 64 61 74 61 20 77 65 72 65 20 65 6e 63 72 79 70 74 65 64 } //Your network has been breached and all data were encrypted  10
		$a_80_1 = {59 6f 75 20 77 69 6c 6c 20 6e 6f 74 20 6f 6e 6c 79 20 72 65 63 65 69 76 65 20 61 20 64 65 63 72 79 70 74 6f 72 } //You will not only receive a decryptor  1
		$a_80_2 = {5f 52 45 41 44 4d 45 5f 2e 74 78 74 } //_README_.txt  1
		$a_80_3 = {2e 64 6c 6c 2e 73 79 73 2e 65 78 65 2e 64 72 76 2e 63 6f 6d 2e 63 61 74 } //.dll.sys.exe.drv.com.cat  1
	condition:
		((#a_80_0  & 1)*10+(#a_80_1  & 1)*1+(#a_80_2  & 1)*1+(#a_80_3  & 1)*1) >=13
 
}