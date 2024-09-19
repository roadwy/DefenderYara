
rule Trojan_Win32_Convagent_QAA_MTB{
	meta:
		description = "Trojan:Win32/Convagent.QAA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {c1 e8 05 89 45 70 8b 45 70 03 85 10 ff ff ff 8d 14 3b 33 c2 33 c1 29 85 1c ff ff ff 83 3d 94 58 0f 02 0c c7 05 ?? ?? ?? ?? ee 3d ea f4 89 45 70 75 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}