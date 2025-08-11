
rule Trojan_Win32_AutoHK_GP_MTB{
	meta:
		description = "Trojan:Win32/AutoHK.GP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 02 00 00 "
		
	strings :
		$a_01_0 = {4c 6f 6f 70 0a 7b 0a 49 66 20 28 20 57 69 6e 43 6c 6f 73 65 20 3c 20 52 75 6e 57 61 69 74 20 29 0a 7b 0a 4c 6f 6f 70 0a 7b 0a 49 66 20 28 20 25 41 5f 53 63 72 69 70 74 44 69 72 25 20 3c 20 52 75 6e } //5
		$a_01_1 = {20 46 69 6c 65 44 65 6c 65 74 65 20 29 0a 7b 0a 7d 0a 49 66 20 28 20 52 65 67 52 65 61 64 20 3c 20 45 6e 76 47 65 74 20 29 0a 7b 0a 7d 0a 49 66 20 28 20 44 6c 6c 43 61 6c } //1
	condition:
		((#a_01_0  & 1)*5+(#a_01_1  & 1)*1) >=6
 
}