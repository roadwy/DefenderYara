
rule Trojan_Win32_Emotet_DSP_MTB{
	meta:
		description = "Trojan:Win32/Emotet.DSP!MTB,SIGNATURE_TYPE_PEHSTR,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {8a 44 24 1c 8a d0 8a d9 f6 d2 f6 d3 0a d3 0a c1 22 d0 88 16 } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}