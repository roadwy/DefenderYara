
rule Trojan_BAT_RenameFiles_AYA_MTB{
	meta:
		description = "Trojan:BAT/RenameFiles.AYA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 "
		
	strings :
		$a_01_0 = {73 6f 75 72 63 65 5c 72 65 70 6f 73 5c 72 66 5c 72 66 5c 6f 62 6a 5c 44 65 62 75 67 5c 72 66 2e 70 64 62 } //2 source\repos\rf\rf\obj\Debug\rf.pdb
		$a_01_1 = {24 32 64 34 64 62 64 31 33 2d 63 33 64 61 2d 34 32 34 32 2d 38 31 34 32 2d 37 33 66 37 63 66 66 62 35 64 37 30 } //1 $2d4dbd13-c3da-4242-8142-73f7cffb5d70
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*1) >=3
 
}