
rule Trojan_BAT_Androm_ARR_MTB{
	meta:
		description = "Trojan:BAT/Androm.ARR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,14 00 14 00 04 00 00 "
		
	strings :
		$a_81_0 = {24 34 34 32 37 64 35 61 33 2d 35 39 39 65 2d 34 34 66 36 2d 61 66 66 33 2d 65 30 38 61 66 63 30 62 61 66 61 64 } //6 $4427d5a3-599e-44f6-aff3-e08afc0bafad
		$a_81_1 = {3c 4d 6f 64 75 6c 65 3e 7b 64 32 30 34 38 61 39 63 2d 36 36 34 37 2d 34 62 30 37 2d 61 65 33 32 2d 34 36 34 35 39 61 61 37 30 65 33 63 7d } //3 <Module>{d2048a9c-6647-4b07-ae32-46459aa70e3c}
		$a_81_2 = {43 6a 6d 74 79 64 70 6b 2e 65 78 65 } //10 Cjmtydpk.exe
		$a_81_3 = {53 64 4b 42 48 42 33 2f 68 70 2b 77 36 2b 6f 61 6f 4b 70 31 48 41 3d 3d } //1 SdKBHB3/hp+w6+oaoKp1HA==
	condition:
		((#a_81_0  & 1)*6+(#a_81_1  & 1)*3+(#a_81_2  & 1)*10+(#a_81_3  & 1)*1) >=20
 
}