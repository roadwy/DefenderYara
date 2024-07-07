
rule Trojan_Win32_PlugX_psyP_MTB{
	meta:
		description = "Trojan:Win32/PlugX.psyP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 01 00 00 "
		
	strings :
		$a_01_0 = {ff 96 28 9c 01 00 8b ae 30 9c 01 00 8d be 00 f0 ff ff bb 00 10 00 00 50 54 6a 04 53 57 ff d5 8d 87 d7 01 00 00 80 20 7f 80 60 28 7f 58 50 54 50 53 57 ff d5 58 61 8d 44 24 80 6a 00 39 c4 75 fa 83 ec 80 e9 4f c4 fe ff } //7
	condition:
		((#a_01_0  & 1)*7) >=7
 
}