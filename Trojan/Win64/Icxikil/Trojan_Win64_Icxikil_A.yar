
rule Trojan_Win64_Icxikil_A{
	meta:
		description = "Trojan:Win64/Icxikil.A,SIGNATURE_TYPE_PEHSTR_EXT,04 00 03 00 04 00 00 "
		
	strings :
		$a_01_0 = {5c 00 44 00 65 00 76 00 69 00 63 00 65 00 5c 00 4b 00 49 00 4c 00 4c 00 49 00 53 00 } //1 \Device\KILLIS
		$a_01_1 = {53 79 73 65 6e 74 65 72 20 68 6f 6f 6b 65 64 } //1 Sysenter hooked
		$a_01_2 = {26 72 69 3d 25 73 26 6d 63 3d 25 73 26 76 73 3d 25 73 26 64 71 3d 25 73 26 73 64 3d 25 73 26 6f 73 3d 25 73 26 73 63 3d 25 73 26 74 6d 3d 25 73 26 6b 65 79 3d 25 73 } //1 &ri=%s&mc=%s&vs=%s&dq=%s&sd=%s&os=%s&sc=%s&tm=%s&key=%s
		$a_01_3 = {66 65 69 74 75 33 32 45 6a 36 34 5c 50 72 6f 63 65 73 73 4f 70 65 72 5c 57 69 6e 37 52 65 6c 65 61 73 65 5c 50 72 6f 63 65 73 73 4f 70 65 72 2e 70 64 62 } //1 feitu32Ej64\ProcessOper\Win7Release\ProcessOper.pdb
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=3
 
}