
rule Trojan_Win64_FormBook_AKF_MTB{
	meta:
		description = "Trojan:Win64/FormBook.AKF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {c6 44 24 65 17 c6 44 24 64 96 c6 44 24 63 7b c6 44 24 62 75 c6 44 24 61 74 c6 44 24 60 70 c6 44 24 5f 7d c6 44 24 5e 7d c6 44 24 5d 78 c6 44 24 5c 9d c6 44 24 5b 6e c6 44 24 5a 7f c6 44 24 59 7d c6 44 24 58 99 c6 44 24 57 7a c6 44 24 56 74 c6 44 24 55 50 c6 44 24 54 89 c6 44 24 53 76 c6 44 24 52 77 c6 44 24 51 6f c6 44 24 50 63 48 8d 4c 24 4c 48 8d 54 24 6a e8 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}