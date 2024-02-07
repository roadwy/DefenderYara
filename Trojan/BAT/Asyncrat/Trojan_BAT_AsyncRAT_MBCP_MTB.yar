
rule Trojan_BAT_AsyncRAT_MBCP_MTB{
	meta:
		description = "Trojan:BAT/AsyncRAT.MBCP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_01_0 = {07 09 41 00 07 09 73 00 07 09 73 00 07 09 65 00 07 09 6d 00 07 09 62 00 07 09 6c 00 07 09 79 00 07 09 01 03 07 09 01 1d 07 09 07 09 07 09 07 09 07 09 07 09 07 09 07 09 07 09 07 09 } //00 00  इAइsइsइeइmइbइlइyइ́इᴁइइइइइइइइइइ
	condition:
		any of ($a_*)
 
}