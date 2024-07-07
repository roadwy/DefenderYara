
rule Trojan_BAT_Tedy_RX_MTB{
	meta:
		description = "Trojan:BAT/Tedy.RX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 03 00 00 "
		
	strings :
		$a_01_0 = {06 28 0e 00 00 06 6f 06 00 00 0a 17 8d 08 00 00 01 25 16 1f 0a 9d 17 6f 07 00 00 0a 0b 07 8e 69 17 32 1c 07 16 9a 6f 08 00 00 0a 80 04 00 00 04 07 17 9a 6f 08 00 00 0a 80 05 00 00 04 2b 14 } //4
		$a_01_1 = {3c 50 72 69 76 61 74 65 49 6d 70 6c 65 6d 65 6e 74 61 74 69 6f 6e 44 65 74 61 69 6c 73 3e 7b 34 38 38 46 44 43 46 43 2d 37 42 45 41 2d 34 41 44 34 2d 39 45 32 39 2d 32 38 37 46 43 36 39 37 38 34 43 35 7d } //1 <PrivateImplementationDetails>{488FDCFC-7BEA-4AD4-9E29-287FC69784C5}
		$a_01_2 = {76 00 69 00 72 00 75 00 73 00 74 00 6f 00 74 00 61 00 6c 00 42 00 79 00 70 00 61 00 73 00 73 00 2e 00 65 00 78 00 65 00 } //1 virustotalBypass.exe
	condition:
		((#a_01_0  & 1)*4+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=6
 
}