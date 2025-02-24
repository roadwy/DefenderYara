
rule Trojan_Win64_Redcap_ARDP_MTB{
	meta:
		description = "Trojan:Win64/Redcap.ARDP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {48 89 5c 24 38 48 89 44 24 48 48 8b 10 48 89 54 24 40 48 8b 58 08 48 89 5c 24 30 48 8d 0d ?? ?? 1e 00 bf 0b 00 00 00 48 89 d0 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}