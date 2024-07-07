
rule Trojan_BAT_AgentTesla_JTN_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.JTN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {02 06 02 8e 69 6a 5d d4 02 06 02 8e 69 6a 5d d4 91 03 06 03 8e 69 6a 5d d4 91 61 02 06 17 6a 58 02 8e 69 6a 5d d4 91 59 20 00 01 00 00 58 20 00 01 00 00 5d d2 9c 06 17 6a 58 0a } //1
		$a_00_1 = {33 34 37 32 34 63 63 65 2d 33 63 33 64 2d 34 37 65 38 2d 39 30 39 36 2d 63 65 63 36 30 36 61 64 39 65 61 65 } //1 34724cce-3c3d-47e8-9096-cec606ad9eae
	condition:
		((#a_01_0  & 1)*1+(#a_00_1  & 1)*1) >=2
 
}