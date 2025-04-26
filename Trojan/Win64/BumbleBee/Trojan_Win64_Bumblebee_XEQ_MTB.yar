
rule Trojan_Win64_Bumblebee_XEQ_MTB{
	meta:
		description = "Trojan:Win64/Bumblebee.XEQ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {42 31 0c 12 49 83 c2 04 8b 83 ec 00 00 00 ff c8 01 43 54 48 8b 0d 42 7f 05 00 8b 83 d0 00 00 00 01 81 80 00 00 00 b8 d1 92 19 00 2b 05 03 80 05 00 01 83 f8 00 00 00 48 8b 15 1e 7f 05 00 8b 8a e0 00 00 00 03 8a 90 00 00 00 8b 42 78 0f af c1 89 42 78 8b 05 67 7f 05 00 83 c0 ee 09 83 ec 00 00 00 49 81 fa 40 05 06 00 7c 81 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}