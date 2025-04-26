
rule Trojan_Win64_IcedID_NA_MTB{
	meta:
		description = "Trojan:Win64/IcedID.NA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 07 00 00 "
		
	strings :
		$a_01_0 = {37 48 69 58 41 2e 64 6c 6c } //1 7HiXA.dll
		$a_01_1 = {43 43 45 39 55 44 7a 54 62 } //1 CCE9UDzTb
		$a_01_2 = {59 46 49 77 44 6a 75 51 4c 4f 4c } //1 YFIwDjuQLOL
		$a_01_3 = {61 66 37 32 48 72 } //1 af72Hr
		$a_01_4 = {68 61 73 64 6e 75 68 61 73 } //1 hasdnuhas
		$a_01_5 = {6d 63 66 4e 69 6e 4c 74 6a } //1 mcfNinLtj
		$a_01_6 = {72 73 6c 37 37 58 32 43 36 73 33 } //1 rsl77X2C6s3
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1) >=7
 
}