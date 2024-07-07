
rule Trojan_Win32_DarkGate_RPX_MTB{
	meta:
		description = "Trojan:Win32/DarkGate.RPX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {8b 8d c4 f9 ff ff 83 c4 1c ff 71 1c ff 95 ac f9 ff ff 8b 85 c4 f9 ff ff 53 8b 9d b0 f9 ff ff 8b 40 10 83 c0 38 50 ff d3 8b 85 c4 f9 ff ff ff b5 b4 f9 ff ff 8b 40 10 83 c0 40 50 ff d3 68 04 01 00 00 8d 85 e0 f9 ff ff 50 6a 00 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}