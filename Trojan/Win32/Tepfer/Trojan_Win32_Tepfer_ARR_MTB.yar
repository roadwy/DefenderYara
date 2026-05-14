
rule Trojan_Win32_Tepfer_ARR_MTB{
	meta:
		description = "Trojan:Win32/Tepfer.ARR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,32 00 32 00 02 00 00 "
		
	strings :
		$a_03_0 = {8b 44 24 30 8b 58 ?? 8b 4c 24 2c 33 19 8b 70 } //10
		$a_81_1 = {69 64 3d 31 59 42 56 49 44 6b 5a 67 79 67 4e 66 55 55 32 72 62 4a 58 58 43 59 64 72 7a 61 79 35 72 4d 64 59 } //40 id=1YBVIDkZgygNfUU2rbJXXCYdrzay5rMdY
	condition:
		((#a_03_0  & 1)*10+(#a_81_1  & 1)*40) >=50
 
}