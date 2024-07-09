
rule Trojan_Win32_Emotet_ML_MTB{
	meta:
		description = "Trojan:Win32/Emotet.ML!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {8d 49 00 66 8b 10 83 c0 02 66 85 d2 75 ?? 2b c6 d1 f8 8b f0 8b c1 33 d2 f7 f6 41 8a 04 53 30 44 39 ff 3b cd } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}