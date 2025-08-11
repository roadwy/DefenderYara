
rule Trojan_Win64_Dacic_SEC_MTB{
	meta:
		description = "Trojan:Win64/Dacic.SEC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 "
		
	strings :
		$a_01_0 = {2a 75 39 4a 6d 6d 58 2a 4c 46 44 39 44 31 } //2 *u9JmmX*LFD9D1
		$a_01_1 = {74 56 23 2a 76 56 39 69 34 65 78 36 7a 57 } //1 tV#*vV9i4ex6zW
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*1) >=3
 
}