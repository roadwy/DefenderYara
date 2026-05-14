
rule Trojan_BAT_Jalapeno_MCQ_MTB{
	meta:
		description = "Trojan:BAT/Jalapeno.MCQ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {24 32 32 37 37 61 31 62 62 2d 37 34 35 65 2d 34 64 61 37 2d 61 34 39 33 2d 65 38 31 66 39 39 36 66 65 64 61 62 } //1 $2277a1bb-745e-4da7-a493-e81f996fedab
		$a_01_1 = {5f 75 70 64 61 74 65 2e 65 78 65 } //1 _update.exe
		$a_01_2 = {63 6f 73 74 75 72 61 2e 63 6f 73 74 75 72 61 2e 70 64 62 2e 63 6f 6d 70 72 65 73 73 65 64 } //1 costura.costura.pdb.compressed
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}