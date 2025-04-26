
rule Trojan_Win64_Bumblebee_MIP_MTB{
	meta:
		description = "Trojan:Win64/Bumblebee.MIP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {48 2b d8 49 8b 80 d0 03 00 00 49 8b 90 a8 02 00 00 48 8b 88 50 03 00 00 48 81 e9 49 1c 00 00 48 09 8a c8 03 00 00 49 8b 80 28 01 00 00 49 8b 90 e0 03 00 00 48 8b 88 c8 03 00 00 49 03 cf 48 31 8a f0 01 00 00 41 8a 0c 3c 2a 8c 24 98 00 00 00 32 8c 24 90 00 00 00 49 8b 40 50 88 0c 07 83 fe 08 0f 84 84 02 00 00 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}