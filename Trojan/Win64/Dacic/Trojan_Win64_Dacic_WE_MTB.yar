
rule Trojan_Win64_Dacic_WE_MTB{
	meta:
		description = "Trojan:Win64/Dacic.WE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {61 72 63 74 69 63 2e 70 64 62 } //1 arctic.pdb
		$a_01_1 = {73 74 61 72 74 20 63 6d 64 20 2f 43 20 22 63 6f 6c 6f 72 20 62 20 26 26 20 74 69 74 6c 65 20 45 72 72 6f 72 20 26 26 20 65 63 68 6f } //1 start cmd /C "color b && title Error && echo
		$a_01_2 = {63 65 72 74 75 74 69 6c 20 2d 68 61 73 68 66 69 6c 65 20 } //1 certutil -hashfile 
		$a_01_3 = {26 26 20 74 69 6d 65 6f 75 74 20 2f 74 20 35 } //1 && timeout /t 5
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}