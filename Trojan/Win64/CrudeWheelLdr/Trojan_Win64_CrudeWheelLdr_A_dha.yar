
rule Trojan_Win64_CrudeWheelLdr_A_dha{
	meta:
		description = "Trojan:Win64/CrudeWheelLdr.A!dha,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {49 83 c5 0f 49 2b ff 4d 2b e7 49 c1 ee 04 0f 1f 80 ?? ?? ?? ?? 41 0f 10 34 1c 49 8d 34 1c 4c 8b c3 48 8b d6 48 8d 4d ?? e8 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}