
rule Trojan_Win32_PonyStealer_EP_MTB{
	meta:
		description = "Trojan:Win32/PonyStealer.EP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_81_0 = {83 e9 04 81 fc 7b db 57 6e ff 34 0f 90 8f 04 08 81 fc 1f ed 57 6e 31 34 08 eb 08 00 00 00 00 00 00 00 00 85 c9 75 d9 } //1
	condition:
		((#a_81_0  & 1)*1) >=1
 
}