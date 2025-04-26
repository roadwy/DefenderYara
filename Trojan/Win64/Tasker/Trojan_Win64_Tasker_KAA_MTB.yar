
rule Trojan_Win64_Tasker_KAA_MTB{
	meta:
		description = "Trojan:Win64/Tasker.KAA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {49 89 f3 41 8b 03 49 ba ?? ?? ?? ?? ?? ?? ?? ?? 48 8d 76 18 48 83 ee 14 eb } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}