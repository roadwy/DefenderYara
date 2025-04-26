
rule Trojan_BAT_Discord_N_MTB{
	meta:
		description = "Trojan:BAT/Discord.N!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {55 00 73 00 65 00 72 00 73 00 5c 00 4c 00 69 00 73 00 61 00 5c 00 41 00 70 00 70 00 44 00 61 00 74 00 61 00 5c 00 52 00 6f 00 61 00 6d 00 69 00 6e 00 67 00 5c 00 4c 00 69 00 6d 00 65 00 } //1 Users\Lisa\AppData\Roaming\Lime
		$a_01_1 = {57 00 69 00 6e 00 64 00 6f 00 77 00 73 00 20 00 53 00 65 00 63 00 75 00 72 00 69 00 74 00 79 00 20 00 48 00 65 00 61 00 6c 00 74 00 68 00 20 00 53 00 65 00 72 00 76 00 69 00 63 00 65 00 65 00 78 00 65 00 } //1 Windows Security Health Serviceexe
		$a_01_2 = {53 79 73 74 65 6d 2e 57 65 62 2e 53 65 72 76 69 63 65 73 2e 50 72 6f 74 6f 63 6f 6c 73 2e 53 6f 61 70 48 74 74 70 43 6c 69 65 6e 74 50 72 6f 74 6f 63 6f 6c } //1 System.Web.Services.Protocols.SoapHttpClientProtocol
		$a_01_3 = {54 68 72 65 61 64 53 61 66 65 4f 62 6a 65 63 74 50 72 6f 76 69 64 65 72 } //1 ThreadSafeObjectProvider
		$a_01_4 = {4d 79 57 65 62 53 65 72 76 69 63 65 73 4f 62 6a 65 63 74 50 72 6f 76 69 64 65 72 } //1 MyWebServicesObjectProvider
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}