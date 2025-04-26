
rule Trojan_Win64_CobaltStrike_KVM_MTB{
	meta:
		description = "Trojan:Win64/CobaltStrike.KVM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {45 33 c0 4c 8d 4c 24 ?? b8 f7 12 da 4b 41 f7 e8 c1 fa 04 8b c2 c1 e8 1f 03 d0 0f be c2 6b c8 36 41 8a c0 41 ff c0 2a c1 04 37 41 30 01 49 ff c1 41 83 f8 ?? 7c d2 4c 8d 44 24 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}