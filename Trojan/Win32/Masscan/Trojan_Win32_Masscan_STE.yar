
rule Trojan_Win32_Masscan_STE{
	meta:
		description = "Trojan:Win32/Masscan.STE,SIGNATURE_TYPE_PEHSTR,05 00 05 00 06 00 00 "
		
	strings :
		$a_01_0 = {6d 61 74 63 68 20 25 73 20 6d } //1 match %s m
		$a_01_1 = {69 73 73 75 65 72 5b 4b 61 73 70 65 72 73 6b 79 } //1 issuer[Kaspersky
		$a_01_2 = {4d 41 4e 3a 20 22 73 73 64 70 3a 64 69 73 63 6f 76 65 72 22 } //1 MAN: "ssdp:discover"
		$a_01_3 = {2d 2d 20 62 6c 61 63 6b 72 6f 63 6b } //1 -- blackrock
		$a_01_4 = {6d 61 73 73 63 61 6e 20 2d 70 38 30 2c 38 30 30 30 2d 38 31 30 30 20 31 30 2e 30 2e 30 2e 30 2f 38 } //1 masscan -p80,8000-8100 10.0.0.0/8
		$a_01_5 = {73 75 62 6a 65 63 74 5b 53 6f 6d 65 4f 72 67 61 6e 69 7a 61 74 69 6f 6e 61 6c 55 6e 69 74 5d } //1 subject[SomeOrganizationalUnit]
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=5
 
}