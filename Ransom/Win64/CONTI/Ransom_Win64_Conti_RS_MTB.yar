
rule Ransom_Win64_Conti_RS_MTB{
	meta:
		description = "Ransom:Win64/Conti.RS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {41 0f b6 11 4d 8d 49 01 b8 ?? ?? ?? ?? 2b c2 8d 0c 40 b8 ?? ?? ?? ?? c1 e1 03 f7 e9 03 d1 c1 fa 06 8b c2 c1 e8 1f 03 d0 6b c2 7f 2b c8 b8 ?? ?? ?? ?? 83 c1 7f f7 e9 03 d1 c1 fa 06 8b c2 c1 e8 1f 03 d0 6b c2 7f 2b c8 41 88 49 ff 49 83 ea 01 75 ae } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}