
rule Trojan_Win64_Sessiter_B_dha{
	meta:
		description = "Trojan:Win64/Sessiter.B!dha,SIGNATURE_TYPE_PEHSTR_EXT,64 00 64 00 01 00 00 "
		
	strings :
		$a_43_0 = {81 ec 08 00 00 00 66 b9 90 01 02 e8 00 00 00 00 66 89 4c 24 08 48 81 ec a8 01 00 00 ba 08 00 00 00 b9 01 00 00 00 e8 90 00 00 } //100
	condition:
		((#a_43_0  & 1)*100) >=100
 
}