
rule Ransom_Win32_BlackMagic_PA_MTB{
	meta:
		description = "Ransom:Win32/BlackMagic.PA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {2e 42 6c 61 63 6b 4d 61 67 69 63 } //1 .BlackMagic
		$a_01_1 = {5c 48 61 63 6b 65 64 42 79 42 6c 61 63 6b 4d 61 67 69 63 2e 74 78 74 } //1 \HackedByBlackMagic.txt
		$a_01_2 = {42 6c 61 63 6b 20 4d 61 67 69 63 20 48 61 73 20 54 61 72 67 65 74 65 64 20 59 6f 75 21 } //1 Black Magic Has Targeted You!
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}