
rule Trojan_Win32_ChirpingSand_A_dha{
	meta:
		description = "Trojan:Win32/ChirpingSand.A!dha,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_42_0 = {d2 8d 0c 3e 8b c6 46 f7 75 90 01 01 8a 82 90 01 04 8b 55 90 01 01 32 04 0a 88 01 3b f3 90 00 00 } //1
	condition:
		((#a_42_0  & 1)*1) >=1
 
}