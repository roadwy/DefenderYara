
rule Trojan_Win64_Rootkit_CCIM_MTB{
	meta:
		description = "Trojan:Win64/Rootkit.CCIM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {48 8d 44 24 38 41 b9 3f 01 0f 00 45 33 c0 48 89 44 24 20 48 8d 15 5a 33 01 00 48 c7 c1 02 00 00 80 ff 15 2d bc 00 00 85 c0 75 12 48 8b 4c 24 38 48 8d 15 55 33 01 00 ff 15 f7 bb } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}