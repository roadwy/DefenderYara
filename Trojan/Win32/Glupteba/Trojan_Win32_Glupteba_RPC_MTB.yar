
rule Trojan_Win32_Glupteba_RPC_MTB{
	meta:
		description = "Trojan:Win32/Glupteba.RPC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_02_0 = {39 d2 74 01 ea 31 0b 90 01 04 81 c3 04 00 00 00 39 f3 75 eb 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_Glupteba_RPC_MTB_2{
	meta:
		description = "Trojan:Win32/Glupteba.RPC!MTB,SIGNATURE_TYPE_PEHSTR,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_01_0 = {31 10 4e 47 81 c0 01 00 00 00 01 f7 01 ff 39 d8 75 } //00 00 
	condition:
		any of ($a_*)
 
}