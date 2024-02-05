
rule Trojan_Win32_RedLine_MN_MTB{
	meta:
		description = "Trojan:Win32/RedLine.MN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 0a 00 "
		
	strings :
		$a_01_0 = {89 f0 31 d2 b9 7b 05 00 00 f7 75 14 8b 45 08 c1 ea 02 0f be 04 10 69 c0 ec 0d 00 00 99 f7 f9 b2 33 0f af c2 30 04 33 46 eb } //00 00 
	condition:
		any of ($a_*)
 
}