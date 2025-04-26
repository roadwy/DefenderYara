
rule Ransom_MSIL_Gommyrypt_A{
	meta:
		description = "Ransom:MSIL/Gommyrypt.A,SIGNATURE_TYPE_PEHSTR,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {2f 00 62 00 74 00 63 00 2e 00 74 00 78 00 74 00 } //1 /btc.txt
		$a_01_1 = {46 00 75 00 63 00 6b 00 20 00 6f 00 66 00 66 00 2e 00 } //1 Fuck off.
		$a_01_2 = {54 00 6d 00 46 00 6f 00 4c 00 67 00 3d 00 3d 00 } //1 TmFoLg==
		$a_01_3 = {51 00 55 00 78 00 4d 00 49 00 45 00 39 00 47 00 49 00 46 00 6c 00 50 00 56 00 56 00 49 00 67 00 52 00 6b 00 6c 00 4d 00 52 00 56 00 4d 00 67 00 53 00 45 00 46 00 57 00 52 00 53 00 42 00 43 00 52 00 55 00 56 00 4f 00 49 00 45 00 56 00 4f 00 51 00 31 00 4a 00 5a 00 55 00 46 00 52 00 46 00 52 00 43 00 45 00 3d 00 } //2 QUxMIE9GIFlPVVIgRklMRVMgSEFWRSBCRUVOIEVOQ1JZUFRFRCE=
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*2) >=4
 
}