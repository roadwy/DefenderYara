
rule Trojan_Win32_IcedId_DEC_MTB{
	meta:
		description = "Trojan:Win32/IcedId.DEC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {83 c4 10 53 6a 01 53 53 8d 44 24 28 50 ff 15 ?? ?? ?? ?? 85 c0 75 3a 6a 08 6a 01 53 53 8d 4c 24 28 51 ff 15 90 1b 00 85 c0 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}