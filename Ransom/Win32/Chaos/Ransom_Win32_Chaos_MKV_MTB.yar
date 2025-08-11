
rule Ransom_Win32_Chaos_MKV_MTB{
	meta:
		description = "Ransom:Win32/Chaos.MKV!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_01_0 = {41 8b c3 30 10 83 c2 0d 80 e2 ff 40 49 75 f4 } //5
	condition:
		((#a_01_0  & 1)*5) >=5
 
}