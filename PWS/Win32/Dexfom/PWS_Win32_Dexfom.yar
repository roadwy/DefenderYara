
rule PWS_Win32_Dexfom{
	meta:
		description = "PWS:Win32/Dexfom,SIGNATURE_TYPE_PEHSTR_EXT,03 00 02 00 03 00 00 "
		
	strings :
		$a_01_0 = {ff 52 14 0b c0 75 5e 57 8d bd b6 fc ff ff 6a 00 6a 00 68 04 01 00 00 57 8b 55 10 52 8b 12 ff 52 0c 0b c0 75 40 } //1
		$a_01_1 = {81 38 2e 7a 64 00 75 0c c7 45 ec 02 00 00 00 e9 } //1
		$a_01_2 = {03 42 0c 89 47 0c c7 07 2e 7a 64 00 8b 4a 14 03 4a 10 ff 76 3c } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=2
 
}