
rule Trojan_Win64_SantaStealer_BYD_MTB{
	meta:
		description = "Trojan:Win64/SantaStealer.BYD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {0f b6 4c 05 fd 30 4c 06 fd 0f b6 4c 05 fe 30 4c 06 fe 0f b6 4c 05 ff 30 4c 06 ff 0f b6 4c 05 00 30 0c 06 48 83 c0 04 48 83 f8 43 75 d3 eb 9f } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}