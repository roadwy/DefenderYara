
rule Trojan_Win64_BManager_E{
	meta:
		description = "Trojan:Win64/BManager.E,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {73 70 79 69 5f 72 74 68 5f 69 6e 73 70 65 63 74 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 20 00 00 4f ae 00 00 ?? ?? 00 00 ?? ?? 01 73 62 6d } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}