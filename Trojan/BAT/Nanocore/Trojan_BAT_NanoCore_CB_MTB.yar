
rule Trojan_BAT_NanoCore_CB_MTB{
	meta:
		description = "Trojan:BAT/NanoCore.CB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 01 00 "
		
	strings :
		$a_01_0 = {45 56 42 5f 38 34 37 34 41 46 34 43 41 42 31 42 41 34 38 36 5f 30 30 30 30 30 45 33 30 } //01 00  EVB_8474AF4CAB1BA486_00000E30
		$a_01_1 = {61 6e 69 6d 61 74 69 6f 6e 2e 52 65 6e 64 65 72 4e 6f 64 65 41 6e 69 6d 61 74 6f 72 2e 6d 6f 64 75 6c 65 39 2e 65 78 65 } //01 00  animation.RenderNodeAnimator.module9.exe
		$a_01_2 = {73 65 74 5f 53 65 63 75 72 69 74 79 50 72 6f 74 6f 63 6f 6c } //01 00  set_SecurityProtocol
		$a_01_3 = {57 65 62 52 65 71 75 65 73 74 } //01 00  WebRequest
		$a_01_4 = {71 76 69 72 74 75 61 6c 62 6f 78 67 6c 6f 62 61 6c 73 75 6e 69 74 } //00 00  qvirtualboxglobalsunit
	condition:
		any of ($a_*)
 
}