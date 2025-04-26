
rule Trojan_Win64_Shelm_RB_MTB{
	meta:
		description = "Trojan:Win64/Shelm.RB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {48 83 ec 28 33 c0 83 f8 01 74 0d b9 60 ea 00 00 ff 15 ?? ?? ?? ?? eb ec 48 83 c4 28 c3 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}