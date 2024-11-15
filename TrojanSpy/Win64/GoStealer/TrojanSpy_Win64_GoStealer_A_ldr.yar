
rule TrojanSpy_Win64_GoStealer_A_ldr{
	meta:
		description = "TrojanSpy:Win64/GoStealer.A!ldr,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {48 2b 45 eb 8b 55 88 4c 89 8d e3 fe ff ?? 89 95 ef fe ff ff 4c 01 4d e2 89 8d 7c fe ff ff 49 89 cb } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}