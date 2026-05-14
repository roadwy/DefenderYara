
rule Trojan_Win64_AmberShoal_A{
	meta:
		description = "Trojan:Win64/AmberShoal.A,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {c6 44 24 48 4c c6 44 24 49 8b } //2
		$a_01_1 = {0f be 00 83 f8 78 75 } //1
		$a_01_2 = {78 78 78 78 00 } //1
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}