
rule Trojan_Win64_Convagent_TPAA_MTB{
	meta:
		description = "Trojan:Win64/Convagent.TPAA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_01_0 = {ff c2 48 63 ca 0f b6 04 19 88 04 1f 44 88 0c 19 0f b6 0c 1f 49 03 c9 0f b6 c1 0f b6 04 18 41 30 02 49 ff c2 49 8b c2 49 2b c6 49 3b c3 72 a3 } //5
	condition:
		((#a_01_0  & 1)*5) >=5
 
}