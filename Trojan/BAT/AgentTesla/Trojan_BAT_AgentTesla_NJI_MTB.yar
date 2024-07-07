
rule Trojan_BAT_AgentTesla_NJI_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.NJI!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0d 00 0d 00 05 00 00 "
		
	strings :
		$a_01_0 = {24 30 37 30 61 64 31 36 65 2d 62 66 38 32 2d 34 64 39 62 2d 61 38 30 30 2d 64 32 63 38 62 64 35 32 37 36 30 61 } //10 $070ad16e-bf82-4d9b-a800-d2c8bd52760a
		$a_01_1 = {24 37 61 66 34 37 61 30 33 2d 66 61 62 66 2d 34 35 38 62 2d 62 65 36 66 2d 34 66 38 62 65 66 38 39 61 37 65 36 } //10 $7af47a03-fabf-458b-be6f-4f8bef89a7e6
		$a_01_2 = {47 65 74 50 69 78 65 6c } //1 GetPixel
		$a_01_3 = {43 6f 6c 6f 72 54 72 61 6e 73 6c 61 74 6f 72 } //1 ColorTranslator
		$a_01_4 = {54 6f 57 69 6e 33 32 } //1 ToWin32
	condition:
		((#a_01_0  & 1)*10+(#a_01_1  & 1)*10+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=13
 
}