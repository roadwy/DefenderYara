
rule Trojan_BAT_Tnega_ABM_MTB{
	meta:
		description = "Trojan:BAT/Tnega.ABM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 07 00 00 01 00 "
		
	strings :
		$a_01_0 = {57 bf a3 3f 09 0f 00 00 00 fa 01 33 00 16 c4 00 01 00 00 00 0a 01 00 00 f7 00 00 00 f3 02 00 00 a1 06 00 00 4d 08 00 00 } //01 00 
		$a_01_1 = {54 72 61 6e 73 66 6f 72 6d 46 69 6e 61 6c 42 6c 6f 63 6b } //01 00  TransformFinalBlock
		$a_01_2 = {47 65 74 4d 61 6e 69 66 65 73 74 52 65 73 6f 75 72 63 65 53 74 72 65 61 6d } //01 00  GetManifestResourceStream
		$a_01_3 = {43 72 65 61 74 65 44 65 63 72 79 70 74 6f 72 } //01 00  CreateDecryptor
		$a_01_4 = {66 00 63 00 66 00 30 00 66 00 65 00 66 00 32 00 66 00 34 00 38 00 39 00 34 00 30 00 64 00 63 00 63 00 30 00 39 00 61 00 61 00 62 00 33 00 38 00 38 00 33 00 31 00 39 00 33 00 30 00 39 00 31 00 } //01 00  fcf0fef2f48940dcc09aab3883193091
		$a_01_5 = {23 3d 7a 56 74 79 38 4f 65 4b 61 34 71 6e 31 31 42 42 69 57 73 61 46 61 24 68 41 34 53 70 79 } //01 00  #=zVty8OeKa4qn11BBiWsaFa$hA4Spy
		$a_01_6 = {23 3d 7a 43 32 33 77 67 4c 6a 6b 39 52 31 51 74 61 59 4c 5f 58 65 46 74 53 36 74 77 74 34 7a } //00 00  #=zC23wgLjk9R1QtaYL_XeFtS6twt4z
	condition:
		any of ($a_*)
 
}