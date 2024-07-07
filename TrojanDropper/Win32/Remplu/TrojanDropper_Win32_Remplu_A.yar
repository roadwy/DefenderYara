
rule TrojanDropper_Win32_Remplu_A{
	meta:
		description = "TrojanDropper:Win32/Remplu.A,SIGNATURE_TYPE_PEHSTR,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {70 6c 75 67 25 64 00 00 25 73 64 69 72 65 63 74 78 73 25 64 2e 64 61 74 00 00 00 00 70 6c 75 67 00 00 00 00 63 6f 75 6e 74 00 00 00 5b 70 6c 75 67 5d 0d 0a } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}