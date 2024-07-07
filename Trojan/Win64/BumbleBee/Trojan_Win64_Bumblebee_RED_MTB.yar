
rule Trojan_Win64_Bumblebee_RED_MTB{
	meta:
		description = "Trojan:Win64/Bumblebee.RED!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {03 cf 0f af c1 49 63 c8 89 05 90 01 04 48 8b 05 fb 2a 04 00 88 14 01 8b 0d ba 2a 04 00 8b 05 54 2b 04 00 03 cf 05 3a a5 f9 ff 89 0d a7 2a 04 00 31 05 ad 2a 04 00 48 8b 05 90 01 04 48 63 c9 44 88 0c 01 8b 05 7d 2a 04 00 01 3d 87 2a 04 00 05 09 97 f6 ff 48 8b 15 90 01 04 8b 8a fc 00 00 00 03 c8 8b 05 c1 2a 04 00 05 0c 92 f8 ff 89 0d 52 2a 04 00 01 82 94 00 00 00 8b 05 46 2a 04 00 48 8b 0d 90 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}