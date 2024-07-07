
rule Trojan_Win32_GandCrypt_PVE_MTB{
	meta:
		description = "Trojan:Win32/GandCrypt.PVE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_02_0 = {6a 00 ff 15 90 01 04 ff 15 90 01 04 e8 90 01 04 30 04 37 8d 85 fc f7 ff ff 50 6a 00 ff 15 90 01 04 46 3b 75 08 7c 90 00 } //2
	condition:
		((#a_02_0  & 1)*2) >=2
 
}