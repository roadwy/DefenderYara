
rule PWS_BAT_Cidekoq_A{
	meta:
		description = "PWS:BAT/Cidekoq.A,SIGNATURE_TYPE_PEHSTR,08 00 08 00 06 00 00 "
		
	strings :
		$a_01_0 = {4f 76 69 64 69 79 2e 65 78 65 } //3 Ovidiy.exe
		$a_01_1 = {48 74 74 70 57 65 62 52 65 71 75 65 73 74 } //2 HttpWebRequest
		$a_01_2 = {53 79 73 74 65 6d 2e 6e 65 74 } //2 System.net
		$a_01_3 = {48 45 4e 4b 46 41 50 4e 4d 47 48 4c 45 46 4a 47 48 48 4c 44 50 4a 44 48 45 44 48 48 43 42 4b 42 4a 4a 50 41 } //1 HENKFAPNMGHLEFJGHHLDPJDHEDHHCBKBJJPA
		$a_01_4 = {4f 76 69 64 69 79 2e 67 2e 72 65 73 6f 75 72 63 65 73 } //1 Ovidiy.g.resources
		$a_01_5 = {43 6f 6e 66 75 73 65 72 45 78 } //1 ConfuserEx
	condition:
		((#a_01_0  & 1)*3+(#a_01_1  & 1)*2+(#a_01_2  & 1)*2+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=8
 
}