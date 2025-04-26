
rule Trojan_Win64_ZLoader_DF_MTB{
	meta:
		description = "Trojan:Win64/ZLoader.DF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0c 00 0c 00 03 00 00 "
		
	strings :
		$a_03_0 = {33 c9 41 81 c0 b6 2f 00 00 44 8d 49 ?? ff 15 90 09 07 00 44 8b 83 } //10
		$a_80_1 = {58 56 52 47 75 65 } //XVRGue  1
		$a_80_2 = {72 41 4a 55 65 75 4e 66 4e 53 43 52 } //rAJUeuNfNSCR  1
	condition:
		((#a_03_0  & 1)*10+(#a_80_1  & 1)*1+(#a_80_2  & 1)*1) >=12
 
}