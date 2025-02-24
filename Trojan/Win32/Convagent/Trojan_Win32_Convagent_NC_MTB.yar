
rule Trojan_Win32_Convagent_NC_MTB{
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