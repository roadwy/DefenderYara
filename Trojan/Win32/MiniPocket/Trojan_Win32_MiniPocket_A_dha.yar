
rule Trojan_Win32_MiniPocket_A_dha{
	meta:
		description = "Trojan:Win32/MiniPocket.A!dha,SIGNATURE_TYPE_PEHSTR_EXT,64 00 64 00 01 00 00 "
		
	strings :
		$a_41_0 = {c7 8b d7 8b cf 35 07 18 00 65 81 f2 31 e0 bf 08 81 f1 11 9b 24 15 00 } //100
	condition:
		((#a_41_0  & 1)*100) >=100
 
}