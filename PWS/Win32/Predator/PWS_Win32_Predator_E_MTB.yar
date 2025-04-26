
rule PWS_Win32_Predator_E_MTB{
	meta:
		description = "PWS:Win32/Predator.E!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {c6 04 31 6b eb 10 c6 04 31 63 eb 0a c6 04 31 75 eb 04 c6 04 31 66 } //1
		$a_01_1 = {5c 41 70 70 6c 69 63 61 74 69 6f 6e 20 44 61 74 61 5c 70 74 73 74 } //1 \Application Data\ptst
		$a_01_2 = {5c 41 70 70 6c 69 63 61 74 69 6f 6e 20 44 61 74 61 5c 7a 70 61 72 2e 7a 69 70 } //1 \Application Data\zpar.zip
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}