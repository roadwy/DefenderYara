
rule Trojan_Win32_Nekark_MBV_MTB{
	meta:
		description = "Trojan:Win32/Nekark.MBV!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 "
		
	strings :
		$a_01_0 = {73 65 5c 4d 6f 64 69 66 69 65 64 50 72 6f 63 74 61 74 69 63 2e 70 64 62 } //1 se\ModifiedProctatic.pdb
		$a_01_1 = {44 00 4f 00 20 00 59 00 4f 00 55 00 20 00 57 00 41 00 4e 00 54 00 20 00 54 00 4f 00 20 00 45 00 58 00 45 00 43 00 55 00 54 00 45 00 20 00 54 00 48 00 49 00 53 00 20 00 4d 00 41 00 4c 00 57 00 41 00 52 00 45 00 } //2 DO YOU WANT TO EXECUTE THIS MALWARE
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*2) >=3
 
}