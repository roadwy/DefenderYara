
rule Trojan_Win64_Tedy_GHN_MTB{
	meta:
		description = "Trojan:Win64/Tedy.GHN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0b 00 0b 00 02 00 00 "
		
	strings :
		$a_01_0 = {45 89 f4 41 c0 fc 02 45 00 ec 83 c5 02 46 88 24 38 41 89 ef 0f b6 6c 24 67 40 80 fd 40 74 11 41 c0 e6 06 44 00 f5 4d 63 f7 41 ff c7 42 88 2c 30 45 31 ed e9 } //10
		$a_01_1 = {4e 54 49 33 4e 54 5a 6c 4e 44 45 33 4d 77 3d 3d } //1 NTI3NTZlNDE3Mw==
	condition:
		((#a_01_0  & 1)*10+(#a_01_1  & 1)*1) >=11
 
}