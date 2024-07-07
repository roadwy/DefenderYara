
rule Trojan_Win64_SystemBC_RPZ_MTB{
	meta:
		description = "Trojan:Win64/SystemBC.RPZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {fe c3 8a 94 2b c0 fb ff ff 02 c2 8a 8c 28 c0 fb ff ff 88 8c 2b c0 fb ff ff 88 94 28 c0 fb ff ff 02 ca 8a 8c 29 c0 fb ff ff 30 0e 48 ff c6 48 ff cf } //1
		$a_01_1 = {62 61 63 6b 63 6f 6e 6e 65 63 74 5c 73 65 72 76 65 72 2e 65 78 65 } //1 backconnect\server.exe
		$a_01_2 = {5f 6c 6f 61 64 65 72 2e 64 61 74 } //1 _loader.dat
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}