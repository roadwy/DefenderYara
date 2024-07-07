
rule Trojan_BAT_Redcap_RDC_MTB{
	meta:
		description = "Trojan:BAT/Redcap.RDC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 "
		
	strings :
		$a_01_0 = {63 64 38 62 61 39 36 66 2d 30 32 31 64 2d 34 38 37 64 2d 38 66 61 36 2d 65 38 30 63 61 62 38 38 65 31 36 34 } //1 cd8ba96f-021d-487d-8fa6-e80cab88e164
		$a_01_1 = {8e 69 5d 91 61 d2 9c 00 06 06 4a 17 58 54 } //2
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*2) >=3
 
}