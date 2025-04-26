
rule Trojan_Win32_IcedId_DBR_MTB{
	meta:
		description = "Trojan:Win32/IcedId.DBR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {83 c4 0c 53 6a 01 53 53 8d 44 24 ?? 50 ff 15 ?? ?? ?? ?? 85 c0 75 3d 6a 08 6a 01 53 53 8d 4c 24 90 1b 00 51 ff 15 90 1b 01 85 c0 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}