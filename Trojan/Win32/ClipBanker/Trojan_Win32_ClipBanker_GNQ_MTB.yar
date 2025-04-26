
rule Trojan_Win32_ClipBanker_GNQ_MTB{
	meta:
		description = "Trojan:Win32/ClipBanker.GNQ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 02 00 00 "
		
	strings :
		$a_01_0 = {45 32 ea 41 0f 4b eb } //5
		$a_01_1 = {41 52 49 ff c2 41 d0 ea 44 31 34 24 } //5
	condition:
		((#a_01_0  & 1)*5+(#a_01_1  & 1)*5) >=10
 
}