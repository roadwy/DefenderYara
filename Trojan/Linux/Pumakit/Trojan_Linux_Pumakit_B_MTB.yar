
rule Trojan_Linux_Pumakit_B_MTB{
	meta:
		description = "Trojan:Linux/Pumakit.B!MTB,SIGNATURE_TYPE_ELFHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {83 38 02 75 26 31 ff e8 f2 47 02 00 48 89 df be 41 00 00 00 ba ed 01 00 00 31 c0 e8 a8 e1 01 00 85 c0 78 07 89 c7 } //1
		$a_01_1 = {48 89 d9 41 89 c0 31 c0 e8 06 52 02 00 48 89 df e8 8b e1 01 00 bf 54 00 00 00 4c 89 f6 31 c0 e8 08 ff 01 00 85 c0 0f 85 fb 22 00 00 48 8d 3d ee 14 03 00 31 f6 31 c0 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}