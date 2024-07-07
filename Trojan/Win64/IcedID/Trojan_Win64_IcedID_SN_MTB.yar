
rule Trojan_Win64_IcedID_SN_MTB{
	meta:
		description = "Trojan:Win64/IcedID.SN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_03_0 = {48 89 c2 48 83 ca 90 01 01 0f 10 0c 11 48 8b 55 90 01 01 f3 0f 7f 04 02 49 89 c0 49 81 c8 90 01 04 f3 42 90 01 04 48 05 90 01 04 4c 8b 45 90 01 01 4c 39 c0 48 90 01 03 75 90 00 } //1
		$a_01_1 = {53 ad 64 9f e8 fa 46 6b fc 6f 5a f9 e2 37 5f 3c } //1
		$a_01_2 = {4c f2 c0 28 40 ec ec a9 a7 d2 53 c6 ad 7e 0b 27 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}