
rule Trojan_Win32_Bunitucrypt_RFA_MTB{
	meta:
		description = "Trojan:Win32/Bunitucrypt.RFA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 03 00 00 "
		
	strings :
		$a_03_0 = {8a a5 08 00 c7 90 02 05 0e 00 00 00 90 00 } //1
		$a_03_1 = {31 02 83 05 90 01 04 04 83 05 90 01 04 04 68 90 01 04 e8 90 01 04 68 90 00 } //1
		$a_03_2 = {2d 00 10 00 00 83 c0 04 90 02 0a 0d 00 00 00 90 00 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1+(#a_03_2  & 1)*1) >=2
 
}