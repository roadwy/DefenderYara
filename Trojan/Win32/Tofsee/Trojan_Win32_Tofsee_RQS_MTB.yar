
rule Trojan_Win32_Tofsee_RQS_MTB{
	meta:
		description = "Trojan:Win32/Tofsee.RQS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {81 f3 07 eb dd 13 81 6c 24 90 01 01 52 ef 6f 62 b8 41 e5 64 03 81 6c 24 90 01 01 68 19 2a 14 81 44 24 90 01 01 be 08 9a 76 8b 4c 24 90 01 01 8b f7 d3 e6 03 74 24 90 01 01 81 3d 90 01 04 1a 0c 00 00 90 00 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}