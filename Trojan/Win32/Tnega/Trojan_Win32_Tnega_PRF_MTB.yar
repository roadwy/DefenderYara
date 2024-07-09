
rule Trojan_Win32_Tnega_PRF_MTB{
	meta:
		description = "Trojan:Win32/Tnega.PRF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {89 5d fc 8b 45 fc 8a 14 38 8b 4d f8 c0 ca 03 32 91 ?? ?? ?? ?? 6a 0c 88 14 38 8d 41 01 99 59 f7 f9 ff 45 fc 89 55 f8 39 75 fc 7c d7 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}