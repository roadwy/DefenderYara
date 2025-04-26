
rule Trojan_Win64_MeduzaStealer_IKV_MTB{
	meta:
		description = "Trojan:Win64/MeduzaStealer.IKV!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_01_0 = {8b c2 c1 e8 1f 03 d0 0f be c2 6b c8 35 0f b6 c3 ff c3 2a c1 04 31 41 30 40 ff 83 fb 1a 7c d3 } //5
	condition:
		((#a_01_0  & 1)*5) >=5
 
}