
rule Trojan_BAT_Nanocore_NEAA_MTB{
	meta:
		description = "Trojan:BAT/Nanocore.NEAA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0e 00 0e 00 05 00 00 "
		
	strings :
		$a_01_0 = {24 64 65 31 35 33 32 39 33 2d 35 64 65 38 2d 34 36 63 63 2d 39 39 65 63 2d 65 31 32 61 32 38 33 65 61 31 30 33 } //5 $de153293-5de8-46cc-99ec-e12a283ea103
		$a_01_1 = {61 61 39 46 5a 78 44 69 6e 41 6e 77 57 58 50 4a 63 6c 68 } //4 aa9FZxDinAnwWXPJclh
		$a_01_2 = {41 48 64 68 45 67 44 76 34 46 49 4f 78 73 66 39 51 77 70 } //2 AHdhEgDv4FIOxsf9Qwp
		$a_01_3 = {4c 64 63 5f 49 34 5f 4d 31 } //2 Ldc_I4_M1
		$a_01_4 = {6e 57 34 6c 42 61 63 6a 70 63 } //1 nW4lBacjpc
	condition:
		((#a_01_0  & 1)*5+(#a_01_1  & 1)*4+(#a_01_2  & 1)*2+(#a_01_3  & 1)*2+(#a_01_4  & 1)*1) >=14
 
}