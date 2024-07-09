
rule Trojan_Win32_IcedId_SIBP_MTB{
	meta:
		description = "Trojan:Win32/IcedId.SIBP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_00_0 = {53 00 75 00 67 00 67 00 65 00 73 00 74 00 73 00 74 00 65 00 70 00 } //1 Suggeststep
		$a_03_1 = {04 ff 4c 24 ?? [0-10] 90 18 [0-b0] 8b 54 24 ?? 8b 12 [0-30] 8b 7c 24 ?? 81 c2 ?? ?? ?? ?? 89 17 } //1
	condition:
		((#a_00_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}