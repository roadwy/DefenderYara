
rule Trojan_Win64_XWormRAT_A_MTB{
	meta:
		description = "Trojan:Win64/XWormRAT.A!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 03 00 00 "
		
	strings :
		$a_01_0 = {67 6f 2d 72 75 6e 70 65 } //2 go-runpe
		$a_01_1 = {63 69 70 68 65 72 2e 4e 65 77 43 46 42 44 65 63 72 79 70 74 65 72 } //2 cipher.NewCFBDecrypter
		$a_01_2 = {69 6f 75 74 69 6c 2e 54 65 6d 70 44 69 72 } //2 ioutil.TempDir
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2+(#a_01_2  & 1)*2) >=6
 
}