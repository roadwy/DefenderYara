
rule Trojan_Win64_Spyloader_GPN_MTB{
	meta:
		description = "Trojan:Win64/Spyloader.GPN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 01 00 00 "
		
	strings :
		$a_01_0 = {31 c0 49 b8 8d 3f 25 1b eb e9 53 0f 48 89 ca 90 48 89 c1 4d 89 c1 83 e1 07 48 c1 e1 03 49 d3 e9 44 30 0c 02 48 83 c0 01 48 83 f8 16 75 e2 } //4
	condition:
		((#a_01_0  & 1)*4) >=4
 
}