
rule Ransom_Win32_FileCryptor_PB_MTB{
	meta:
		description = "Ransom:Win32/FileCryptor.PB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {6c 00 6f 00 63 00 6b 00 2e 00 6c 00 6f 00 63 00 6b 00 65 00 64 00 28 00 29 00 } //1 lock.locked()
		$a_01_1 = {46 50 5f 4e 4f 5f 48 4f 53 54 5f 43 48 45 43 4b 3d } //1 FP_NO_HOST_CHECK=
		$a_01_2 = {2e 00 5c 00 43 00 6f 00 62 00 61 00 6c 00 74 00 2d 00 43 00 6c 00 69 00 65 00 6e 00 74 00 2d 00 6c 00 6f 00 67 00 2e 00 74 00 78 00 74 00 } //1 .\Cobalt-Client-log.txt
		$a_03_3 = {5c 43 6f 62 61 6c 74 5c [0-10] 5c [0-10] 5c 43 6c 69 65 6e 74 5c 43 6f 62 61 6c 74 2e 43 6c 69 65 6e 74 2e 70 64 62 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_03_3  & 1)*1) >=4
 
}