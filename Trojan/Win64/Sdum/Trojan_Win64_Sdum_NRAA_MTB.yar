
rule Trojan_Win64_Sdum_NRAA_MTB{
	meta:
		description = "Trojan:Win64/Sdum.NRAA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 02 00 00 "
		
	strings :
		$a_01_0 = {69 6e 66 69 6e 69 74 79 63 68 65 61 74 73 5c 47 61 6d 65 48 65 6c 70 65 72 73 4c 6f 61 64 65 72 5f 5f 41 50 45 58 5f 4e 45 57 5c 47 61 6d 65 48 65 6c 70 65 72 73 4c 6f 61 64 65 72 5f 5f 41 50 45 58 5f 4e 45 57 5c 62 69 6e 5c 78 36 34 5c 52 65 6c 65 61 73 65 5c 6e 65 74 38 2e 30 2d 77 69 6e 64 6f 77 73 5c 77 69 6e 2d 78 36 34 5c 6e 61 74 69 76 65 5c 41 70 65 78 4c 6f 61 64 65 72 2e 70 64 62 } //4 infinitycheats\GameHelpersLoader__APEX_NEW\GameHelpersLoader__APEX_NEW\bin\x64\Release\net8.0-windows\win-x64\native\ApexLoader.pdb
		$a_01_1 = {28 c0 f1 71 6c a1 9f 22 6c a1 9f 22 6c a1 9f 22 } //1
	condition:
		((#a_01_0  & 1)*4+(#a_01_1  & 1)*1) >=5
 
}