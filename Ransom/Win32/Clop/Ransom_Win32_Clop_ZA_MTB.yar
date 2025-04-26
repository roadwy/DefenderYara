
rule Ransom_Win32_Clop_ZA_MTB{
	meta:
		description = "Ransom:Win32/Clop.ZA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {25 00 73 00 5c 00 52 00 45 00 41 00 44 00 4d 00 45 00 5f 00 52 00 45 00 41 00 44 00 4d 00 45 00 2e 00 74 00 78 00 74 00 } //1 %s\README_README.txt
		$a_01_1 = {66 6f 72 20 2f 46 20 22 74 6f 6b 65 6e 73 3d 2a 22 20 25 31 20 69 6e 20 28 27 77 65 76 74 75 74 69 6c 2e 65 78 65 20 65 6c 27 29 20 44 4f 20 77 65 76 74 75 74 69 6c 2e 65 78 65 20 63 6c 20 22 25 31 22 } //1 for /F "tokens=*" %1 in ('wevtutil.exe el') DO wevtutil.exe cl "%1"
		$a_01_2 = {25 00 73 00 20 00 72 00 75 00 6e 00 72 00 75 00 6e 00 } //1 %s runrun
		$a_01_3 = {25 00 73 00 25 00 73 00 2e 00 43 00 49 00 49 00 70 00 } //1 %s%s.CIIp
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}