
rule Trojan_Win32_IcedId_SIBJ17_MTB{
	meta:
		description = "Trojan:Win32/IcedId.SIBJ17!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {31 d2 4c 8d 05 ?? ?? ?? ?? 80 44 24 ?? ?? c0 64 24 90 1b 01 ?? 8a 4c 24 90 1b 01 88 4c 24 ?? 41 8a 4c 50 ?? 88 4c 24 90 1b 01 80 44 24 90 1b 01 ?? 8a 4c 24 90 1b 01 08 4c 24 90 1b 06 8a 4c 24 ?? 30 4c 24 90 1b 06 fe 44 24 90 1b 0d 8a 4c 24 90 1b 06 88 0c 10 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}