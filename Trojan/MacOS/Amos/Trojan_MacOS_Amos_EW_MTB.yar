
rule Trojan_MacOS_Amos_EW_MTB{
	meta:
		description = "Trojan:MacOS/Amos.EW!MTB,SIGNATURE_TYPE_MACHOHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {4c 89 e0 48 83 c8 07 48 8d 48 01 48 83 f8 17 41 bd 1a 00 00 00 4c 0f 45 e9 4c 89 ef e8 f1 37 00 00 49 89 c7 49 83 cd 01 4c 89 ad 80 fc ff ff 48 89 85 90 fc ff ff 4c 89 a5 88 fc ff ff 45 89 ec 44 8b ad 60 fd ff ff } //1
		$a_01_1 = {89 8d 68 fd ff ff 44 89 a5 60 fd ff ff 4c 89 f8 48 83 c8 07 4c 8d 60 01 48 83 f8 17 b8 1a 00 00 00 4c 0f 44 e0 4c 89 e7 e8 f9 2d 00 00 49 89 c5 49 83 cc 01 4c 89 a5 40 fd ff ff 48 89 85 50 fd ff ff 4c 89 bd 48 fd ff ff 45 89 e7 44 8b a5 60 fd ff ff 8b 8d 68 fd ff ff } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}