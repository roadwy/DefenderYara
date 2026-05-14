
rule Trojan_Win32_ValleyRAT_PGVR_MTB{
	meta:
		description = "Trojan:Win32/ValleyRAT.PGVR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_01_0 = {0f 57 84 24 a0 00 00 00 0f 29 84 24 a0 00 00 00 0f 28 84 24 50 02 00 00 0f 57 84 24 b0 00 00 00 0f 29 84 24 b0 00 00 00 0f 28 84 24 30 03 00 00 0f 57 84 24 c0 00 00 00 0f 29 84 24 c0 00 00 00 0f 28 44 24 40 0f 57 84 24 d0 00 00 00 0f 29 84 24 d0 00 00 00 } //5
	condition:
		((#a_01_0  & 1)*5) >=5
 
}