
rule Trojan_Win32_Convagent_NC_MTB{
	meta:
		description = "Trojan:Win32/Convagent.NC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 03 00 00 "
		
	strings :
		$a_01_0 = {72 f4 8a 85 ee fa ff ff c6 85 fc fe ff ff 20 84 c0 74 2e 8d 9d ef fa ff ff 0f b6 c8 0f b6 03 3b c8 77 16 2b c1 } //3
		$a_01_1 = {44 00 69 00 68 00 79 00 62 00 72 00 69 00 64 00 73 00 2e 00 65 00 78 00 65 00 } //1 Dihybrids.exe
		$a_01_2 = {4c 6f 61 64 52 65 73 6f 75 72 63 65 } //1 LoadResource
	condition:
		((#a_01_0  & 1)*3+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=5
 
}
rule Trojan_Win32_Convagent_NC_MTB_2{
	meta:
		description = "Trojan:Win32/Convagent.NC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 05 00 00 "
		
	strings :
		$a_01_0 = {50 6c 65 61 73 65 20 52 75 6e 20 41 73 20 55 6c 61 6e 67 20 41 74 61 75 20 52 65 73 74 61 72 74 20 4b 6f 6d 70 75 74 65 72 20 41 6e 64 61 20 41 74 61 75 20 4d 61 74 69 6b 61 6e 20 41 6e 74 69 76 69 72 75 73 20 41 6e 64 61 } //2 Please Run As Ulang Atau Restart Komputer Anda Atau Matikan Antivirus Anda
		$a_01_1 = {53 75 6b 73 65 73 20 49 6e 6a 65 63 74 } //1 Sukses Inject
		$a_01_2 = {76 69 70 2d 66 6e 61 74 69 63 2e 63 6f 6d } //2 vip-fnatic.com
		$a_01_3 = {61 70 69 2d 76 76 69 70 6d 6f 64 73 2e 63 6f 6d } //2 api-vvipmods.com
		$a_01_4 = {48 61 72 61 70 20 42 75 6b 61 20 55 6c 61 6e 67 20 54 6f 6f 6c 73 20 49 6e 6a 65 63 74 69 6f 6e 20 41 74 61 75 20 48 75 62 75 6e 67 69 20 53 65 6c 6c 65 72 20 21 } //1 Harap Buka Ulang Tools Injection Atau Hubungi Seller !
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*1+(#a_01_2  & 1)*2+(#a_01_3  & 1)*2+(#a_01_4  & 1)*1) >=8
 
}