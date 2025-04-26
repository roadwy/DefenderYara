
rule Trojan_Win32_SystemBC_psyR_MTB{
	meta:
		description = "Trojan:Win32/SystemBC.psyR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 01 00 00 "
		
	strings :
		$a_03_0 = {e2 89 85 30 fe ff ff 83 bd 30 fe ff ff ?? 7d 20 6a ?? 68 24 1b 40 00 ff b5 34 fe ff ff ff b5 30 } //7
	condition:
		((#a_03_0  & 1)*7) >=7
 
}