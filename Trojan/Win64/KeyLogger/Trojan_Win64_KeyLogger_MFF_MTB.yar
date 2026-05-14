
rule Trojan_Win64_KeyLogger_MFF_MTB{
	meta:
		description = "Trojan:Win64/KeyLogger.MFF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_01_0 = {48 8b ce 48 8b d7 8a 01 2c 40 34 bc 88 01 48 ff c1 48 ff ca 75 f0 } //5
	condition:
		((#a_01_0  & 1)*5) >=5
 
}