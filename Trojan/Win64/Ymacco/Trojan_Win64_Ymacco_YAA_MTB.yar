
rule Trojan_Win64_Ymacco_YAA_MTB{
	meta:
		description = "Trojan:Win64/Ymacco.YAA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0b 00 0b 00 02 00 00 "
		
	strings :
		$a_03_0 = {41 8b c0 83 e0 3f 2b c8 48 d3 cf 48 8d 0d ?? ?? ?? ?? 49 33 f8 4a 87 bc f1 10 f5 01 00 33 c0 } //10
		$a_01_1 = {2b d1 8a ca 50 90 5a 48 d3 ca } //1
	condition:
		((#a_03_0  & 1)*10+(#a_01_1  & 1)*1) >=11
 
}