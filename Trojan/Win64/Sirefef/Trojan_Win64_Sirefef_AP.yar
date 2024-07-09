
rule Trojan_Win64_Sirefef_AP{
	meta:
		description = "Trojan:Win64/Sirefef.AP,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {44 0f b7 63 06 44 0f b7 5b 14 45 85 e4 74 24 49 8d 7c 1b 2c 8b 17 8b 4f f8 44 8b 47 fc 48 03 55 00 48 03 ce e8 ?? ?? ?? ?? 48 83 c7 28 41 83 c4 ff 75 e1 48 8b 55 ?? 48 8b ce 48 2b 53 30 e8 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}