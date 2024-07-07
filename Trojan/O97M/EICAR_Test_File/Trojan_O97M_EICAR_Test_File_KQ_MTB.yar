
rule Trojan_O97M_EICAR_Test_File_KQ_MTB{
	meta:
		description = "Trojan:O97M/EICAR_Test_File.KQ!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {65 69 63 61 72 50 61 72 74 31 20 3d 20 22 58 35 4f 21 50 25 40 41 50 5b 34 5c 50 5a 58 35 34 28 50 5e 5e 29 37 43 22 } //1 eicarPart1 = "X5O!P%@AP[4\PZX54(P^^)7C"
		$a_01_1 = {65 69 63 61 72 50 61 72 74 32 20 3d 20 22 43 29 37 7d 24 45 49 43 41 52 2d 53 54 41 4e 44 41 52 44 2d 41 4e 54 49 56 49 52 55 53 2d 54 45 53 54 2d 46 49 4c 45 21 24 48 2b 48 2a 22 } //1 eicarPart2 = "C)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"
		$a_01_2 = {53 68 65 6c 6c 20 22 63 6d 64 2e 65 78 65 20 2f 4b 20 65 63 68 6f 20 22 20 2b 20 65 69 63 61 72 50 61 72 74 31 20 2b 20 65 69 63 61 72 50 61 72 74 32 } //1 Shell "cmd.exe /K echo " + eicarPart1 + eicarPart2
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}