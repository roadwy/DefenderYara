
rule Trojan_BAT_AgentTesla_PABX_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.PABX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {65 00 59 00 4f 00 66 00 52 00 67 00 78 00 58 00 37 00 67 00 45 00 43 00 77 00 6e 00 37 00 2b 00 77 00 77 00 36 00 35 00 32 00 67 00 3d 00 3d 00 } //1 eYOfRgxX7gECwn7+ww652g==
		$a_01_1 = {55 00 45 00 55 00 44 00 35 00 68 00 62 00 48 00 49 00 2b 00 77 00 4e 00 33 00 67 00 2f 00 75 00 39 00 64 00 67 00 34 00 53 00 77 00 3d 00 3d 00 } //1 UEUD5hbHI+wN3g/u9dg4Sw==
		$a_01_2 = {64 00 4f 00 2f 00 6c 00 6d 00 4e 00 54 00 33 00 52 00 49 00 35 00 32 00 50 00 31 00 61 00 66 00 4c 00 51 00 70 00 6c 00 46 00 77 00 3d 00 3d 00 } //1 dO/lmNT3RI52P1afLQplFw==
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}