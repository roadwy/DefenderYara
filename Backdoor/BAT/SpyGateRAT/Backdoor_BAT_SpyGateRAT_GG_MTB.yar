
rule Backdoor_BAT_SpyGateRAT_GG_MTB{
	meta:
		description = "Backdoor:BAT/SpyGateRAT.GG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0b 00 0b 00 03 00 00 "
		
	strings :
		$a_80_0 = {5c 52 65 64 20 44 65 76 69 6c 20 53 70 79 47 61 74 65 2d 52 41 54 } //\Red Devil SpyGate-RAT  10
		$a_80_1 = {63 61 6d 2e 44 69 72 65 63 74 58 2e 43 61 70 74 75 72 65 } //cam.DirectX.Capture  1
		$a_80_2 = {73 71 6c 69 74 65 } //sqlite  1
	condition:
		((#a_80_0  & 1)*10+(#a_80_1  & 1)*1+(#a_80_2  & 1)*1) >=11
 
}