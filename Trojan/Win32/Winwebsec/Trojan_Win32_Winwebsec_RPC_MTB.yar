
rule Trojan_Win32_Winwebsec_RPC_MTB{
	meta:
		description = "Trojan:Win32/Winwebsec.RPC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {3b 50 0c 73 3e 8b 58 04 8b ca 8b 50 18 8a 14 0a 32 54 18 60 8b 40 28 88 14 01 8b 45 fc } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}