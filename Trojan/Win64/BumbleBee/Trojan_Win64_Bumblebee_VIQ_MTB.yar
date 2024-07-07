
rule Trojan_Win64_Bumblebee_VIQ_MTB{
	meta:
		description = "Trojan:Win64/Bumblebee.VIQ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {48 98 48 3b c6 0f 8d 90 01 04 4c 8b 6c 24 90 01 01 4c 8d 14 03 4c 2b eb 4c 8b c3 48 2b f0 0f b6 0d 90 01 04 49 8b 83 90 01 04 48 0f af cf 48 09 88 90 01 04 43 8a 0c 2a 2a 4c 24 60 32 4c 24 58 49 8b 43 58 41 88 0c 02 83 fd 08 0f 84 90 01 04 49 8b 53 90 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}