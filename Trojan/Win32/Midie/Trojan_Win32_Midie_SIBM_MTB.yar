
rule Trojan_Win32_Midie_SIBM_MTB{
	meta:
		description = "Trojan:Win32/Midie.SIBM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_00_0 = {5c 69 6e 74 65 67 72 61 6c 5c 64 65 76 69 6c 73 2e 65 78 65 } //1 \integral\devils.exe
		$a_00_1 = {5c 63 68 75 72 63 68 65 73 5c 62 72 6f 63 6b 2e 61 75 } //1 \churches\brock.au
		$a_03_2 = {b9 00 00 00 00 8a 84 0d 90 01 04 81 f9 90 01 04 74 90 01 01 90 02 08 04 90 01 01 90 02 08 2c 90 01 01 90 02 08 34 90 01 01 90 02 08 88 84 0d 90 1b 00 83 c1 01 90 18 8a 84 0d 90 1b 00 81 f9 90 1b 01 90 18 b0 00 b9 00 00 00 00 68 90 01 01 90 01 03 68 90 01 01 90 1b 10 ff 15 90 01 04 50 ff 15 90 01 04 8d 4d 90 01 01 51 6a 40 56 8d 8d 90 1b 00 51 ff d0 8d 85 90 1b 00 ff d0 90 00 } //1
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_03_2  & 1)*1) >=3
 
}