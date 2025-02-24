
rule Trojan_Win32_Neoreblamy_GPPA_MTB{
	meta:
		description = "Trojan:Win32/Neoreblamy.GPPA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 03 00 00 "
		
	strings :
		$a_81_0 = {71 6c 46 44 53 6a 64 66 49 47 4e 56 77 6d 50 44 51 } //3 qlFDSjdfIGNVwmPDQ
		$a_81_1 = {4a 67 65 6b 41 78 4a 6d 51 7a 47 70 47 51 77 78 62 } //2 JgekAxJmQzGpGQwxb
		$a_81_2 = {6d 7a 79 59 52 46 61 66 56 68 66 48 4e 42 44 64 44 51 66 50 50 71 75 } //1 mzyYRFafVhfHNBDdDQfPPqu
	condition:
		((#a_81_0  & 1)*3+(#a_81_1  & 1)*2+(#a_81_2  & 1)*1) >=6
 
}