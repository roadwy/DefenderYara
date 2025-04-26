
rule Trojan_BAT_UmbralStealer_SG_MTB{
	meta:
		description = "Trojan:BAT/UmbralStealer.SG!MTB,SIGNATURE_TYPE_PEHSTR,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {55 6d 62 72 61 6c 2e 70 61 79 6c 6f 61 64 2e 65 78 65 } //1 Umbral.payload.exe
		$a_01_1 = {55 6d 62 72 61 6c 20 53 74 65 61 6c 65 72 20 50 61 79 6c 6f 61 64 } //1 Umbral Stealer Payload
		$a_01_2 = {24 65 38 32 33 63 31 35 61 2d 64 64 61 66 2d 34 64 31 65 2d 61 36 65 62 2d 38 30 36 34 35 64 31 65 65 37 33 35 } //1 $e823c15a-ddaf-4d1e-a6eb-80645d1ee735
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}