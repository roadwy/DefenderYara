
rule Trojan_BAT_AgentTesla_NOI_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.NOI!MTB,SIGNATURE_TYPE_PEHSTR_EXT,10 00 10 00 08 00 00 "
		
	strings :
		$a_01_0 = {24 64 33 61 37 39 62 33 66 2d 61 33 32 34 2d 34 66 31 64 2d 61 63 34 37 2d 38 32 30 34 66 34 32 66 37 39 31 34 } //10 $d3a79b3f-a324-4f1d-ac47-8204f42f7914
		$a_01_1 = {24 38 36 31 32 63 32 33 30 2d 62 61 62 38 2d 34 38 32 36 2d 62 31 61 38 2d 66 31 63 63 39 38 63 35 36 34 33 31 } //10 $8612c230-bab8-4826-b1a8-f1cc98c56431
		$a_01_2 = {74 00 70 00 00 05 73 00 3a 00 00 05 2f 00 2f 00 00 05 63 00 64 00 00 05 6e 00 2e 00 00 05 64 00 69 00 00 05 73 00 63 00 00 05 6f 00 72 00 00 05 64 00 61 00 00 05 70 00 } //1 tpԀs:Ԁ//ԀcdԀn.ԀdiԀscԀorԀdaԀp
		$a_01_3 = {70 00 00 05 2e 00 63 00 00 05 6f 00 6d 00 00 05 2f 00 61 00 00 05 74 00 74 00 00 05 61 00 63 00 00 05 68 00 6d 00 00 05 65 00 6e 00 00 05 74 00 73 00 00 05 2f 00 39 } //1
		$a_80_4 = {63 48 56 7a 61 48 42 79 62 33 68 35 4c 6e 42 31 63 32 68 77 63 6d 39 34 65 51 3d 3d } //cHVzaHByb3h5LnB1c2hwcm94eQ==  1
		$a_01_5 = {46 72 6f 6d 42 61 73 65 36 34 53 74 72 69 6e 67 } //1 FromBase64String
		$a_01_6 = {44 6f 77 6e 6c 6f 61 64 44 61 74 61 } //1 DownloadData
		$a_01_7 = {47 65 74 45 78 65 63 75 74 69 6e 67 41 73 73 65 6d 62 6c 79 } //1 GetExecutingAssembly
	condition:
		((#a_01_0  & 1)*10+(#a_01_1  & 1)*10+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_80_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1) >=16
 
}