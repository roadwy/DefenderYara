
rule Trojan_Win32_IcedID_PKV_MTB{
	meta:
		description = "Trojan:Win32/IcedID.PKV!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_02_0 = {81 c2 5c 60 2d 01 89 15 ?? ?? ?? ?? a1 ?? ?? ?? ?? 03 45 fc 8b 0d ?? ?? ?? ?? 89 88 ?? ?? ff ff 90 09 06 00 8b 15 } //2
	condition:
		((#a_02_0  & 1)*2) >=2
 
}