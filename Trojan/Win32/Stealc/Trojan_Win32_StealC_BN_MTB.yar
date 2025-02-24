
rule Trojan_Win32_StealC_BN_MTB{
	meta:
		description = "Trojan:Win32/StealC.BN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {40 00 00 e0 [0-0b] 1b 00 00 ?? ?? 00 00 ?? 1b 00 00 ?? 28 00 00 00 00 00 00 00 00 00 00 00 00 00 40 00 00 e0 ?? ?? ?? ?? ?? ?? ?? ?? 00 10 00 00 00 ?? ?? 00 00 ?? 00 00 00 ?? 43 00 00 00 00 00 00 00 00 00 00 00 00 00 40 00 00 e0 2e 74 61 67 67 61 6e 74 00 30 } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}