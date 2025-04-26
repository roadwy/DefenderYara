
rule Trojan_Win64_Redline_SIM_MTB{
	meta:
		description = "Trojan:Win64/Redline.SIM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {ba 50 00 00 00 8d 4a d0 e8 06 95 ff ff 4c 8b d8 48 85 c0 75 08 83 c8 ff e9 a2 02 00 00 48 89 05 1f 6d 1f 00 b9 20 00 00 00 89 0d 04 6d 1f 00 48 05 00 0a 00 00 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}