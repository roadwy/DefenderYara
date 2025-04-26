
rule Trojan_Win32_Glupteba_DSH_MTB{
	meta:
		description = "Trojan:Win32/Glupteba.DSH!MTB,SIGNATURE_TYPE_PEHSTR,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {8a d0 8a c8 24 f0 02 c0 02 c0 0a 07 80 e1 fc c0 e2 06 0a 57 02 c0 e1 04 0a 4f 01 88 04 1e 8b 45 10 46 88 0c 1e 46 88 14 1e } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}