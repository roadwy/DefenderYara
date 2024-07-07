
rule TrojanDropper_Win32_Rozena_ARA_MTB{
	meta:
		description = "TrojanDropper:Win32/Rozena.ARA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {89 ca c1 e2 0d 31 ca 89 d6 c1 ee 11 31 d6 89 f1 c1 e1 05 31 f1 89 8c 05 50 ff ff ff 83 c0 04 83 f8 3c 72 dc } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}