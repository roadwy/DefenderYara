
rule Trojan_AndroidOS_Mobidash_T{
	meta:
		description = "Trojan:AndroidOS/Mobidash.T,SIGNATURE_TYPE_DEXHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {32 63 43 77 57 7a 51 52 67 6e 6d 72 45 48 45 51 52 39 4a 77 52 51 3d 3d } //1 2cCwWzQRgnmrEHEQR9JwRQ==
		$a_01_1 = {73 74 75 6e 74 6d 61 73 74 65 72 2e 64 62 } //1 stuntmaster.db
		$a_01_2 = {7a 4c 78 71 5a 68 5a 69 6e 59 62 41 75 63 71 4b 62 79 78 75 6b 67 3d 3d } //1 zLxqZhZinYbAucqKbyxukg==
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}