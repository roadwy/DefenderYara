
rule Ransom_Win32_Royal_PAB_MTB{
	meta:
		description = "Ransom:Win32/Royal.PAB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {c1 ea 02 6b c2 0d 8b d6 2b d0 0f b6 44 95 bc 30 47 02 b8 90 01 04 8b 55 e8 8d 14 17 f7 e2 8d 7f 06 c1 ea 02 6b c2 0d 2b f0 0f b6 44 b5 90 01 01 30 47 fd 8d 04 1f 3d 90 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}