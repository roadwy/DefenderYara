
rule Trojan_Win32_Tepfer_EM_MTB{
	meta:
		description = "Trojan:Win32/Tepfer.EM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {61 50 6d 43 31 32 48 46 64 49 46 59 36 79 47 4a 2d 45 6e 48 2f 64 76 61 4b 44 69 35 63 74 79 4e 49 4f 55 63 45 62 59 53 49 2f 58 2d 36 5f 61 47 47 63 6f 56 55 76 66 67 33 79 49 4e 69 45 2f 31 34 37 4e 36 44 37 4e 76 45 52 6b 6b 4c 68 62 4d 78 74 75 } //1 aPmC12HFdIFY6yGJ-EnH/dvaKDi5ctyNIOUcEbYSI/X-6_aGGcoVUvfg3yINiE/147N6D7NvERkkLhbMxtu
		$a_01_1 = {6d 69 63 6b 65 70 37 36 2f 65 6e 63 64 65 63 } //1 mickep76/encdec
		$a_01_2 = {72 61 73 6b 79 2f 67 6f 2d 6c 7a 6f } //1 rasky/go-lzo
		$a_01_3 = {63 68 72 69 73 70 61 73 73 61 73 2f 73 69 6c 6b 40 76 31 2e 33 2e 30 2f 66 69 6c 65 2e 67 6f } //1 chrispassas/silk@v1.3.0/file.go
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}