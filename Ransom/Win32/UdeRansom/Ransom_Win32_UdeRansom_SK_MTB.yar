
rule Ransom_Win32_UdeRansom_SK_MTB{
	meta:
		description = "Ransom:Win32/UdeRansom.SK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,10 00 10 00 04 00 00 "
		
	strings :
		$a_01_0 = {44 3a 2f 47 6f 50 72 6f 6a 2f 73 72 63 2f 59 6f 75 72 52 61 6e 73 6f 6d 2f 64 61 74 61 2e 67 6f } //5 D:/GoProj/src/YourRansom/data.go
		$a_01_1 = {48 65 79 20 67 75 79 73 2c 20 77 68 79 20 6e 6f 74 20 63 61 72 65 3f } //5 Hey guys, why not care?
		$a_01_2 = {65 00 64 00 75 00 20 00 65 00 64 00 69 00 74 00 69 00 6f 00 6e 00 20 00 6f 00 66 00 20 00 59 00 6f 00 75 00 72 00 52 00 61 00 6e 00 73 00 6f 00 6d 00 } //5 edu edition of YourRansom
		$a_01_3 = {47 6f 20 62 75 69 6c 64 20 49 44 } //1 Go build ID
	condition:
		((#a_01_0  & 1)*5+(#a_01_1  & 1)*5+(#a_01_2  & 1)*5+(#a_01_3  & 1)*1) >=16
 
}