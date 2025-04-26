
rule Trojan_Win32_Fareit_MTB{
	meta:
		description = "Trojan:Win32/Fareit!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {0f 6b df ff 34 1f 0f fd c8 5a 31 f2 09 14 18 0f 67 f9 85 db 75 90 09 03 00 83 eb } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}