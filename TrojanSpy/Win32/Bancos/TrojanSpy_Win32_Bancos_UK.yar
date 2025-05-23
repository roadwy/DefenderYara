
rule TrojanSpy_Win32_Bancos_UK{
	meta:
		description = "TrojanSpy:Win32/Bancos.UK,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 07 00 00 "
		
	strings :
		$a_01_0 = {37 00 34 00 36 00 35 00 36 00 44 00 37 00 30 00 32 00 45 00 37 00 30 00 36 00 43 00 } //1 74656D702E706C
		$a_01_1 = {35 00 37 00 36 00 39 00 36 00 45 00 36 00 34 00 36 00 46 00 37 00 37 00 37 00 33 00 32 00 30 00 34 00 43 00 36 00 39 00 37 00 36 00 36 00 35 00 32 00 30 00 34 00 44 00 36 00 35 00 37 00 33 00 36 00 35 00 36 00 45 00 36 00 37 00 36 00 35 00 37 00 32 00 32 00 30 00 33 00 38 00 32 00 45 00 34 00 39 00 32 00 30 00 32 00 38 00 35 00 30 00 36 00 38 00 36 00 46 00 36 00 45 00 36 00 35 00 32 00 39 00 } //1 57696E646F7773204C697665204D6573656E67657220382E49202850686F6E6529
		$a_01_2 = {32 00 32 00 36 00 38 00 37 00 34 00 37 00 34 00 37 00 30 00 33 00 41 00 32 00 46 00 32 00 46 00 37 00 37 00 37 00 37 00 37 00 37 00 32 00 45 00 36 00 33 00 36 00 43 00 36 00 31 00 37 00 32 00 36 00 46 00 32 00 45 00 36 00 33 00 36 00 46 00 36 00 44 00 32 00 45 00 37 00 30 00 36 00 35 00 32 00 32 00 } //1 22687474703A2F2F7777772E636C61726F2E636F6D2E706522
		$a_01_3 = {34 00 33 00 33 00 41 00 35 00 43 00 35 00 37 00 34 00 39 00 34 00 45 00 34 00 34 00 34 00 46 00 35 00 37 00 35 00 33 00 35 00 43 00 37 00 33 00 37 00 39 00 37 00 33 00 37 00 34 00 36 00 35 00 36 00 44 00 33 00 33 00 33 00 32 00 35 00 43 00 36 00 34 00 37 00 32 00 36 00 39 00 37 00 36 00 36 00 35 00 37 00 32 00 37 00 33 00 35 00 43 00 36 00 35 00 37 00 34 00 36 00 33 00 35 00 43 00 36 00 38 00 36 00 46 00 37 00 33 00 37 00 34 00 37 00 33 00 } //1 433A5C57494E444F57535C73797374656D33325C647269766572735C6574635C686F737473
		$a_01_4 = {33 00 31 00 33 00 32 00 33 00 37 00 32 00 45 00 33 00 30 00 32 00 45 00 33 00 30 00 32 00 45 00 33 00 31 00 32 00 30 00 37 00 37 00 37 00 37 00 37 00 37 00 32 00 45 00 37 00 36 00 36 00 39 00 36 00 31 00 36 00 32 00 36 00 33 00 37 00 30 00 32 00 45 00 36 00 33 00 36 00 46 00 36 00 44 00 32 00 45 00 37 00 30 00 36 00 35 00 } //1 3132372E302E302E31207777772E7669616263702E636F6D2E7065
		$a_01_5 = {24 00 45 00 4e 00 56 00 7b 00 53 00 45 00 52 00 56 00 45 00 52 00 5f 00 50 00 4f 00 52 00 54 00 7d 00 } //1 $ENV{SERVER_PORT}
		$a_01_6 = {43 00 6f 00 6e 00 65 00 63 00 63 00 69 00 6f 00 6e 00 65 00 73 00 3a 00 } //1 Conecciones:
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1) >=5
 
}