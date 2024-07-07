
rule Trojan_Win32_MoriAgent_C_dha{
	meta:
		description = "Trojan:Win32/MoriAgent.C!dha,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_80_0 = {5c 4d 6f 72 69 41 67 65 6e 74 5c 43 6c 69 65 6e 74 5c 43 6f 6d 6d 6f 6e 5c } //\MoriAgent\Client\Common\  1
	condition:
		((#a_80_0  & 1)*1) >=1
 
}