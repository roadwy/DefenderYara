
rule Trojan_BAT_NjRat_NEBF_MTB{
	meta:
		description = "Trojan:BAT/NjRat.NEBF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0c 00 0c 00 06 00 00 "
		
	strings :
		$a_01_0 = {31 37 38 61 38 63 34 33 2d 39 33 61 36 2d 34 65 62 37 2d 61 32 66 63 2d 38 34 33 30 33 39 36 36 62 35 30 65 } //3 178a8c43-93a6-4eb7-a2fc-84303966b50e
		$a_01_1 = {52 6f 62 6f 43 6f 70 2e 65 78 65 } //3 RoboCop.exe
		$a_01_2 = {52 6f 62 6f 43 6f 70 2e 4d 79 } //3 RoboCop.My
		$a_01_3 = {42 2e 72 73 72 63 } //1 B.rsrc
		$a_01_4 = {67 65 74 5f 45 76 69 64 65 6e 63 65 } //1 get_Evidence
		$a_01_5 = {34 53 79 73 74 65 6d 2e 57 65 62 2e 53 65 72 76 69 63 65 73 2e 50 72 6f 74 6f 63 6f 6c 73 2e 53 6f 61 70 48 74 74 70 43 6c 69 65 6e 74 50 72 6f 74 6f 63 6f 6c } //1 4System.Web.Services.Protocols.SoapHttpClientProtocol
	condition:
		((#a_01_0  & 1)*3+(#a_01_1  & 1)*3+(#a_01_2  & 1)*3+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=12
 
}