
rule Trojan_Win64_Rhadamanthys_PKV_MTB{
	meta:
		description = "Trojan:Win64/Rhadamanthys.PKV!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {0f b6 44 04 40 30 41 02 49 8d 47 03 48 03 c1 83 e0 0f 0f b6 44 04 ?? 30 41 03 49 8d 47 04 48 03 c1 83 e0 0f 0f b6 44 04 40 30 41 04 48 83 c1 06 48 83 ea 01 75 } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}