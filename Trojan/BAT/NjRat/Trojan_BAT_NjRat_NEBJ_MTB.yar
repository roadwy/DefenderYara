
rule Trojan_BAT_NjRat_NEBJ_MTB{
	meta:
		description = "Trojan:BAT/NjRat.NEBJ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0f 00 0f 00 02 00 00 "
		
	strings :
		$a_01_0 = {13 0d 11 0d 11 0c 6f 25 00 00 0a 16 13 0e 2b 21 11 09 11 0e 8f 06 00 00 01 25 71 06 00 00 01 11 0c 11 0e 91 61 d2 81 06 00 00 01 11 0e 17 58 13 0e 11 0e 11 08 32 d9 } //10
		$a_01_1 = {57 69 6e 64 6f 77 73 46 6f 72 6d 73 41 70 70 6c 69 63 61 74 69 6f 6e 31 2e 65 78 65 } //5 WindowsFormsApplication1.exe
	condition:
		((#a_01_0  & 1)*10+(#a_01_1  & 1)*5) >=15
 
}