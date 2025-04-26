
rule Trojan_Win64_AsyncRat_ASY_MTB{
	meta:
		description = "Trojan:Win64/AsyncRat.ASY!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 "
		
	strings :
		$a_01_0 = {33 d2 41 8b c5 f7 74 24 24 48 8b 45 a8 44 0f be 0c 02 45 33 c8 48 8b 4f 10 48 8b 57 18 48 3b ca } //2
		$a_01_1 = {6c 6f 61 64 65 72 5c 78 36 34 5c 52 65 6c 65 61 73 65 5c 45 73 70 69 6f 2e 70 64 62 } //1 loader\x64\Release\Espio.pdb
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*1) >=3
 
}