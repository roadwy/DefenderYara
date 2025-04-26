
rule Ransom_Win32_Lambda_MA_MTB{
	meta:
		description = "Ransom:Win32/Lambda.MA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_01_0 = {33 d2 05 c3 ff ff 7f f7 f3 8d 04 31 41 30 10 3b cf 72 } //5
	condition:
		((#a_01_0  & 1)*5) >=5
 
}