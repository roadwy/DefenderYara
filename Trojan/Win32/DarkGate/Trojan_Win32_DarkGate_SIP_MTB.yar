
rule Trojan_Win32_DarkGate_SIP_MTB{
	meta:
		description = "Trojan:Win32/DarkGate.SIP!MTB,SIGNATURE_TYPE_PEHSTR,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {55 68 95 83 40 00 64 ff 30 64 89 20 83 7d fc 00 74 25 8b 45 f8 e8 cf b8 ff ff 50 8d 45 f8 e8 72 ba ff ff 8b d0 8b 45 fc 59 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}