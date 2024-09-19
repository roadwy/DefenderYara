
rule Trojan_Win32_Redline_ASCE_MTB{
	meta:
		description = "Trojan:Win32/Redline.ASCE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 02 00 00 "
		
	strings :
		$a_03_0 = {8a 04 01 8d 4c 24 ?? 30 04 2a e8 ?? ?? ?? ff 8d 4c 24 ?? e8 ?? ?? ?? ff 8d 4c 24 ?? e8 ?? ?? ?? ff 8d 4c 24 ?? e8 ?? ?? ?? ff 8b 7c 24 ?? 46 89 74 24 ?? 3b b4 24 } //4
		$a_01_1 = {41 73 75 63 6a 68 75 64 61 75 6a 73 61 } //1 Asucjhudaujsa
	condition:
		((#a_03_0  & 1)*4+(#a_01_1  & 1)*1) >=5
 
}