
rule Ransom_MSIL_WannaScream_AYA_MTB{
	meta:
		description = "Ransom:MSIL/WannaScream.AYA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 05 00 00 "
		
	strings :
		$a_01_0 = {24 33 62 38 37 65 33 64 62 2d 36 63 38 65 2d 34 37 38 33 2d 39 32 34 37 2d 65 63 66 31 35 38 61 38 64 30 35 39 } //2 $3b87e3db-6c8e-4783-9247-ecf158a8d059
		$a_01_1 = {67 65 74 5f 4b 65 79 44 65 63 72 79 70 74 } //1 get_KeyDecrypt
		$a_01_2 = {44 65 63 72 79 70 74 69 6f 6e 54 6f 6f 6c 2e 50 72 6f 70 65 72 74 69 65 73 2e 52 65 73 6f 75 72 63 65 73 } //1 DecryptionTool.Properties.Resources
		$a_01_3 = {67 65 74 5f 50 72 6f 67 72 61 6d 5f 4d 61 69 6e 5f 44 65 63 72 79 70 74 69 6f 6e 5f 54 6f 6f 6c 73 } //1 get_Program_Main_Decryption_Tools
		$a_80_4 = {44 65 63 72 79 70 74 69 6f 6e 54 6f 6f 6c 2e 65 78 65 } //DecryptionTool.exe  1
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_80_4  & 1)*1) >=6
 
}