
rule Trojan_Win32_BHO_BS{
	meta:
		description = "Trojan:Win32/BHO.BS,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {8d 45 fc bf 80 00 00 00 50 8d 85 ?? ?? ff ff 50 57 68 ?? ?? 01 10 e8 ?? ?? 00 00 83 c4 10 85 c0 74 cd 89 75 fc 50 2b c0 85 c0 58 74 02 e8 04 8d 45 fc 50 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}