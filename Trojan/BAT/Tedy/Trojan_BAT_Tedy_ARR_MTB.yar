
rule Trojan_BAT_Tedy_ARR_MTB{
	meta:
		description = "Trojan:BAT/Tedy.ARR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,14 00 14 00 02 00 00 "
		
	strings :
		$a_01_0 = {5d 58 61 d2 9c 08 17 58 0c 08 06 8e 69 fe 04 0d 09 2d dd } //15
		$a_01_1 = {4b 00 6a 00 51 00 72 00 4f 00 43 00 77 00 73 00 43 00 41 00 51 00 4f 00 44 00 30 00 6f 00 41 00 48 00 67 00 49 00 3d 00 } //5 KjQrOCwsCAQOD0oAHgI=
	condition:
		((#a_01_0  & 1)*15+(#a_01_1  & 1)*5) >=20
 
}
rule Trojan_BAT_Tedy_ARR_MTB_2{
	meta:
		description = "Trojan:BAT/Tedy.ARR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,14 00 14 00 03 00 00 "
		
	strings :
		$a_03_0 = {07 2d 09 16 8d ?? ?? ?? ?? 0d de 24 07 08 6f } //4
		$a_03_1 = {07 02 16 02 8e 69 6f ?? ?? ?? ?? 0c 08 8e 69 1f 10 59 8d ?? ?? ?? ?? 0d 08 1f 10 09 16 09 8e 69 } //10
		$a_01_2 = {74 6d 70 5f 73 74 75 62 2e 65 78 65 } //6 tmp_stub.exe
	condition:
		((#a_03_0  & 1)*4+(#a_03_1  & 1)*10+(#a_01_2  & 1)*6) >=20
 
}
rule Trojan_BAT_Tedy_ARR_MTB_3{
	meta:
		description = "Trojan:BAT/Tedy.ARR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,28 00 28 00 04 00 00 "
		
	strings :
		$a_81_0 = {3c 4d 6f 64 75 6c 65 3e 7b 35 41 35 35 35 33 37 35 2d 46 41 44 39 2d 34 43 35 45 2d 41 46 39 32 2d 37 36 44 42 46 42 43 42 30 45 37 39 7d } //12 <Module>{5A555375-FAD9-4C5E-AF92-76DBFBCB0E79}
		$a_81_1 = {3c 50 72 69 76 61 74 65 49 6d 70 6c 65 6d 65 6e 74 61 74 69 6f 6e 44 65 74 61 69 6c 73 3e 7b 34 34 35 42 41 41 43 41 2d 31 33 46 31 2d 34 42 41 34 2d 41 44 32 38 2d 43 38 37 30 31 46 37 43 45 32 41 36 7d } //19 <PrivateImplementationDetails>{445BAACA-13F1-4BA4-AD28-C8701F7CE2A6}
		$a_81_2 = {3c 4d 6f 64 75 6c 65 3e 7b 61 38 66 30 36 66 30 39 2d 35 38 61 38 2d 34 64 63 39 2d 62 31 65 37 2d 66 63 30 64 63 39 33 32 37 65 32 33 7d } //8 <Module>{a8f06f09-58a8-4dc9-b1e7-fc0dc9327e23}
		$a_81_3 = {2d 2e 65 78 65 } //1 -.exe
	condition:
		((#a_81_0  & 1)*12+(#a_81_1  & 1)*19+(#a_81_2  & 1)*8+(#a_81_3  & 1)*1) >=40
 
}