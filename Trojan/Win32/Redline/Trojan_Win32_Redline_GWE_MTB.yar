
rule Trojan_Win32_Redline_GWE_MTB{
	meta:
		description = "Trojan:Win32/Redline.GWE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {8b 55 08 33 c9 39 4d 0c ?? ?? 8b c1 83 e0 03 8a 80 ?? ?? ?? ?? 30 04 0a 41 3b 4d 0c 72 ec } //10
	condition:
		((#a_03_0  & 1)*10) >=10
 
}