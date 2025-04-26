
rule Trojan_Win32_MsnScar{
	meta:
		description = "Trojan:Win32/MsnScar,SIGNATURE_TYPE_PEHSTR,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {49 20 67 6f 74 20 69 6e 66 65 63 74 65 64 20 6d 79 20 53 63 68 77 61 72 7a 65 20 53 6f 6e 6e 65 20 4d 53 4e 20 53 70 72 65 61 64 65 72 20 3a 28 00 } //1
		$a_01_1 = {0d 0a 68 65 79 00 } //1
		$a_01_2 = {46 4e 3d 56 45 52 44 41 4e 41 3b 20 45 46 3d 42 3b 20 43 4f 3d 46 46 3b 20 43 53 3d 30 3b 20 50 46 3d 32 32 } //1 FN=VERDANA; EF=B; CO=FF; CS=0; PF=22
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}