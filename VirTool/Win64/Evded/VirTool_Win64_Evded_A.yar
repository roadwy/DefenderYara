
rule VirTool_Win64_Evded_A{
	meta:
		description = "VirTool:Win64/Evded.A,SIGNATURE_TYPE_PEHSTR,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {65 6d 61 69 6c 2e 71 75 6f 70 72 69 6d 69 6d 65 } //1 email.quoprimime
		$a_01_1 = {65 76 69 6c 72 64 70 2e 67 75 69 } //1 evilrdp.gui
		$a_01_2 = {76 63 68 61 6e 6e 65 6c 73 } //1 vchannels
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}