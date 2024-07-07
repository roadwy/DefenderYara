
rule Virus_Win32_Seriv_A{
	meta:
		description = "Virus:Win32/Seriv.A,SIGNATURE_TYPE_PEHSTR_EXT,03 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {80 85 71 23 40 00 05 8d 85 5c 23 40 00 50 c3 eb 01 e8 8d b5 79 23 40 00 33 db b9 f4 02 00 00 8b fe 8a 06 46 34 90 01 01 aa 90 01 01 f8 83 fb 01 75 01 c3 90 00 } //2
		$a_03_1 = {5c 53 65 72 76 69 63 65 73 2e 65 78 65 00 90 01 7d e9 8f fc ff 90 00 } //1
	condition:
		((#a_03_0  & 1)*2+(#a_03_1  & 1)*1) >=2
 
}