
rule Trojan_Win32_Convagent_VP_MTB{
	meta:
		description = "Trojan:Win32/Convagent.VP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_02_0 = {85 40 00 58 81 c7 90 01 04 01 d7 e8 90 01 04 81 c7 90 01 04 31 01 01 ff 41 01 d2 39 f1 75 dc 21 fa 4a 90 00 } //10
	condition:
		((#a_02_0  & 1)*10) >=10
 
}