
rule TrojanDropper_Win32_Kilim_B{
	meta:
		description = "TrojanDropper:Win32/Kilim.B,SIGNATURE_TYPE_PEHSTR,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {62 61 63 6b 67 72 6f 75 6e 64 2e 6a 73 9d 52 c1 6a 1b 31 10 bd 07 f2 0f 83 4e 6b 30 eb 1e 7a 4a eb 5e 4a 68 03 29 2d 71 02 05 93 83 2c 8d bd a2 bb 92 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}