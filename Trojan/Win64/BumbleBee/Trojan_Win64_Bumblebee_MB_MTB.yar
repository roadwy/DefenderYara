
rule Trojan_Win64_Bumblebee_MB_MTB{
	meta:
		description = "Trojan:Win64/Bumblebee.MB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {44 0f af 48 6c 8b 48 1c 81 c1 90 01 04 0f af ca 41 8b d1 45 8b c1 c1 ea 10 41 c1 e8 08 89 8e dc 00 00 00 48 8b 05 90 01 04 48 63 48 70 48 8b 05 90 01 04 88 14 01 48 8b 05 90 01 04 ff 40 70 90 00 } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}